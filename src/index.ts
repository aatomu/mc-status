import { connect } from 'cloudflare:sockets';

const segmentBit = 0x7f;
const continueBit = 0x80;

interface result {
	success: boolean;
	message: string;
	data: any;
}

// https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/#response-fields
interface DNSresolve {
	// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
	Status: number;
	// Truncated bit
	TC: boolean;
	// Recursive Desired bit
	RD: boolean;
	// Recursion Available bit
	RA: boolean;
	// All records verified DNSSEC
	AD: boolean;
	// Client asked to disable DNSSEC validation
	CD: boolean;
	Question: {
		name: string;
		// Ask DNS record type
		// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
		type: number;
	}[];
	Answer: DNSrecord[] | undefined; // Record Answer
	Authority: DNSrecord[] | undefined; // Domain record authority (when Answer not found)
	Additional: DNSrecord[] | undefined; // Record additional information
}

interface DNSrecord {
	name: string;
	// record type
	// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
	type: number;
	TTL: number;
	data: string;
}

interface readResult<T> {
	length: number;
	value: T;
}

const protocolVersions: { [mcVersion: string]: number } = {
	'1.21.4': 769,
	'1.21.3': 768,
	'1.21.2': 768,
	'1.21.1': 767,
	'1.21': 767,
	'1.20.6': 766,
	'1.20.5': 766,
	'1.20.4': 765,
	'1.20.3': 765,
	'1.20.2': 764,
	'1.20.1': 763,
	'1.20': 763,
	'1.19.4': 762,
	'1.19.3': 761,
	'1.19.2': 760,
	'1.19.1': 760,
	'1.19': 759,
	'1.18.2': 758,
	'1.18.1': 757,
	'1.18': 757,
	'1.17.1': 756,
	'1.17': 755,
	'1.16.5': 754,
	'1.16.4': 754,
	'1.16.3': 753,
	'1.16.2': 751,
	'1.16.1': 736,
	'1.16': 735,
	'1.15.2': 578,
	'1.15.1': 575,
	'1.15': 573,
	'1.13.2': 404,
	'1.13.1': 401,
	'1.13': 393,
	'1.12.2': 340,
	'1.12.1': 338,
	'1.12': 335,
	'1.11.2': 316,
	'1.11.1': 316,
	'1.11': 315,
	'1.10.2': 210,
	'1.10.1': 210,
	'1.10': 210,
	'1.9.4': 110,
	'1.9.3': 110,
	'1.9.2': 109,
	'1.9.1': 108,
	'1.9': 107,
	'1.8.9': 47,
	'1.8.8': 47,
	'1.8.7': 47,
	'1.8.6': 47,
	'1.8.5': 47,
	'1.8.4': 47,
	'1.8.3': 47,
	'1.8.2': 47,
	'1.8.1': 47,
	'1.8': 47,
	'1.7.10': 5,
	'1.7.9': 5,
	'1.7.8': 5,
	'1.7.7': 5,
	'1.7.6': 5,
	'1.7.5': 4,
	'1.7.4': 4,
	'1.7.3': 4,
	'1.7.2': 4,
	'1.7.1': 3,
	'1.7': 3,
};
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const params = new URLSearchParams(url.searchParams);
		const address = params.get('address');
		if (!address) {
			console.log('address params not found');
			return Return({
				success: false,
				message: 'address params not found',
			} as result);
		}
		const port = params.get('port') || '25565';
		const protocol = (() => {
			const version = params.get('version');
			if (!version) {
				const latestVersion = Object.entries(protocolVersions)[0];
				return latestVersion[1];
			}
			return protocolVersions[version];
		})();
		console.log(protocol);

		// DNS resolve
		const target = await DNSresolve(address, Number(port));
		if (target == undefined) {
			console.log('DNS resolve failed');
			return Return({
				success: false,
				message: 'DNS resolve failed',
			} as result);
		}

		// connect to server
		const socket = await new Promise(async (resolve, reject) => {
			const timer = setTimeout(() => {
				reject('timed out');
			}, 1000);

			console.log(`connect to: ${JSON.stringify(target)}`);
			const socket = connect(target);
			await socket.opened.then(() => {
				clearTimeout(timer);
				console.log(`connection success`);
				resolve(socket);
			});
		})
			.then((socket) => {
				return socket as Socket;
			})
			.catch(() => {
				return null;
			});
		if (!socket) {
			console.log('connection timed out');
			return Return({
				success: false,
				message: 'connection timed out',
			} as result);
		}

		// negotiation to server
		try {
			const writer = socket.writable.getWriter();
			const reader = socket.readable.getReader({ mode: 'byob' });

			// server status request
			// 1.sent handshake
			const handshake = handshakePacket(protocol, target.hostname, target.port);
			console.log(`sent handshake: ${handshake}/${hexDump(handshake)}`);
			writer.write(handshake);
			// 2.sent status request
			const statusRequest = packetGenerator(0x00, new Uint8Array());
			console.log(`sent status request: ${statusRequest}/${hexDump(statusRequest)}`);
			writer.write(statusRequest);
			// 3.sent ping
			const timestamp = new Uint8Array(8);
			new DataView(timestamp.buffer).setBigInt64(0, BigInt(new Date().getTime()));
			const ping = packetGenerator(0x01, timestamp);
			console.log(`sent ping: ${ping}`);
			await writer.write(ping);
			await sleep(50);

			// 4.receive
			await sleep(100);
			const status = await new Promise(async (resolve, reject) => {
				const ticker = setTimeout(reject, 500);

				const length = await readVarInt(reader);
				console.log(`length:${length.value}`);
				const packetId = await readVarInt(reader);
				console.log(`packetID:${packetId.value}`);
				console.log(`data: ${length.value - packetId.length}`);
				const statusLen = await readVarInt(reader);
				console.log(`statusLen:${statusLen.value}`);
				const statusRaw = new TextDecoder().decode(await readN(reader, statusLen.value));
				const status = JSON.parse(statusRaw);

				clearTimeout(ticker);
				resolve(status);
				return;
			})
				.then((status) => {
					return status as object;
				})
				.catch(() => {
					return undefined;
				});

			socket.close();

			if (status == undefined) {
				console.log('server response timed out');
				return Return({
					success: false,
					message: `server response timed out`,
				} as result);
			}

			return Return({
				success: true,
				message: `${address}:${port} connected`,
				data: status,
			} as result);
		} catch (e) {
			console.log(`connection failed: ${e}`);
			return Return({
				success: false,
				message: `connection failed: ${e}`,
			} as result);
		}
	},
} satisfies ExportedHandler<Env>;

async function Return(r: result): Promise<Response> {
	return new Response(JSON.stringify(r, null, '  '), {
		headers: {
			'Content-Type': 'application/json',
			'Access-Control-Allow-Methods': 'GET',
		},
	});
}

async function DNSresolve(address: string, port: number): Promise<SocketAddress | undefined> {
	console.log(`CNAME record resolve request: ${address}`);
	let resolve = await fetch(`https://cloudflare-dns.com/dns-query?name=${address}&type=CNAME`, {
		headers: {
			Accept: 'application/dns-json',
		},
	}).then(async (res) => {
		const resolved = (await res.json()) as unknown as DNSresolve;
		if (!resolved.Answer) {
			console.log(`CNAME resolve failed`);
			return undefined;
		}

		const answer = resolved.Answer;
		console.log(`CNAME resolve success: ${JSON.stringify(answer)}`);
		const aliasedDomain = answer[0].data.replace(/\.$/, '');
		console.log(`CNAME record: ${answer[0].name}=>${answer[0].data}`);
		return { hostname: aliasedDomain, port: port };
	});
	if (resolve != undefined) {
		return resolve;
	}

	console.log(`SRV record resolve request: ${address}`);
	resolve = await fetch(`https://cloudflare-dns.com/dns-query?name=_minecraft._tcp.${address}&type=SRV`, {
		headers: {
			Accept: 'application/dns-json',
		},
	}).then(async (res) => {
		const resolved = (await res.json()) as unknown as DNSresolve;
		if (!resolved.Answer) {
			console.log(`SRV resolve failed`);
			return undefined;
		}

		const answer = resolved.Answer;
		console.log(`SRV resolve success: ${JSON.stringify(answer)}`);

		const info = answer[0].data.split(' ');
		console.log(`CNAME record: ${address}=>${info[3]}:${info[2]}`);

		return { hostname: info[3], port: Number(info[2]) };
	});
	if (resolve != undefined) {
		return resolve;
	}

	return undefined;
}
function writeVarInt(value: number): Uint8Array {
	let buf = new Uint8Array();

	while (true) {
		if (value < continueBit) {
			buf = pushUint8(buf, value);
			return buf;
		}

		buf = pushUint8(buf, (value & segmentBit) | continueBit);
		value = value >>> 7;
	}
}

async function readN(reader: ReadableStreamBYOBReader, n: number): Promise<Uint8Array> {
	let buffer = new ArrayBuffer(n);
	let offset = 0;
	while (offset < buffer.byteLength) {
		const { done, value } = await reader.read(new Uint8Array(buffer, offset, buffer.byteLength - offset));
		if (done) {
			break;
		}
		buffer = value.buffer;
		offset += value.byteLength;
	}
	return new Uint8Array(buffer);
}

async function readVarInt(reader: ReadableStreamBYOBReader): Promise<readResult<number>> {
	let position = 0;
	let length = 0;
	let value = 0;

	while (true) {
		length++;
		const data = await readN(reader, 1);
		const current = data[0];

		value = value | ((current & segmentBit) << position);
		if ((current & continueBit) == 0) {
			break;
		}
		position += 7;

		if (position > 32) {
			break;
		}
	}
	return {
		length: length,
		value: value,
	};
}

function handshakePacket(protocol: number, address: string, port: number): Uint8Array {
	let data = new Uint8Array();

	const protocolVer = writeVarInt(protocol);
	data = concatUint8Array(data, protocolVer);
	const addressBuf = new TextEncoder().encode(address);
	const addressLen = writeVarInt(addressBuf.length);
	data = concatUint8Array(data, addressLen);
	data = concatUint8Array(data, addressBuf);
	const portBuf = new Uint8Array(2);
	new DataView(portBuf.buffer).setUint16(0, port);
	data = concatUint8Array(data, portBuf);
	const next = writeVarInt(1);
	data = concatUint8Array(data, next);

	return packetGenerator(0x00, data);
}

function packetGenerator(packetID: number, data: Uint8Array): Uint8Array {
	let buf = new Uint8Array();
	const packetId = writeVarInt(packetID);
	buf = concatUint8Array(buf, packetId);
	buf = concatUint8Array(buf, data);

	let packet = new Uint8Array();
	const length = writeVarInt(buf.length);
	packet = concatUint8Array(packet, length);
	packet = concatUint8Array(packet, buf);

	return packet;
}

function concatUint8Array(a: Uint8Array, b: Uint8Array): Uint8Array {
	let buf = new Uint8Array(a.byteLength + b.byteLength);
	buf.set(a, 0);
	buf.set(b, a.byteLength);
	return buf;
}

function pushUint8(from: Uint8Array, value: number): Uint8Array {
	let buf = new Uint8Array(from.byteLength + 1);
	buf.set(from, 0);
	new DataView(buf.buffer).setUint8(from.byteLength, value);
	return buf;
}

async function sleep(ms: number): Promise<unknown> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function hexDump(i: Uint8Array): string {
	let text = '';
	i.forEach((v) => {
		text += v.toString(16).padStart(2, '0');
	});
	return text;
}
