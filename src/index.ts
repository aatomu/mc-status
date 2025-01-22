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

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const params = new URLSearchParams(url.searchParams);
		const address = params.get('address');
		if (!address) {
			return Return({
				success: false,
				message: 'address params not found',
			} as result);
		}
		const port = params.get('port') || '25565';

		// DNS resolve
		const target = await DNSresolve(address, Number(port));
		if (target == undefined) {
			return Return({
				success: false,
				message: 'DNS resolve failed',
			} as result);
		}

		// connect to server
		const socket = await new Promise(async (resolve, reject) => {
			const timer = setTimeout(() => {
				console.log(`connection timed out`);
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
			const handshake = handshakePacket(address, target.port);
			console.log(`handshake sent: ${handshake}`);
			await writer.write(handshake);
			await sleep(100);
			// 2.sent status request
			const statusRequest = packetGenerator(0x00, new Uint8Array());
			await writer.write(statusRequest);
			await sleep(50);
			// 3.sent ping request
			const timestamp = new Uint8Array(8);
			new DataView(timestamp.buffer).setBigInt64(0, BigInt(new Date().getTime()));
			const pingRequest = packetGenerator(0x01, timestamp);
			await writer.write(pingRequest);
			await sleep(50);

			// 4.receive
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
				return Return({
					success: false,
					message: `server response missing`,
				} as result);
			}

			return Return({
				success: true,
				message: `${address}:${port} connected`,
				data: status,
			} as result);
		} catch (e) {
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

function handshakePacket(address: string, port: number): Uint8Array {
	let data = new Uint8Array();

	const protocolVer = writeVarInt(3);
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
