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
	data: Uint8Array;
	dataLength: number;
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
		const target = await fetch(`https://cloudflare-dns.com/dns-query?name=_minecraft._tcp.${address}&type=SRV`, {
			headers: {
				Accept: 'application/dns-json',
			},
		}).then(async (res) => {
			const resolved = (await res.json()) as unknown as DNSresolve;
			if (!resolved.Answer) {
				// SRV record not found
				return { hostname: address, port: Number(port) };
			}
			// [0]: Priority,[1]: Weight,[2]: Port,[3]: Target
			const info = resolved.Answer[0].data.split(' ');
			return { hostname: info[3], port: Number(info[2]) };
		});
		// connect to server
		const socket: Socket | null = await new Promise(async (resolve, reject) => {
			const timer = setTimeout(() => {
				reject('timed out');
			}, 1000);
			const socket = connect(target);
			await socket.opened.then(() => {
				clearTimeout(timer);
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
			const reader = socket.readable.getReader();

			// handshake packet
			// 1.sent
			const handshake = handshakePacket();
			console.log(`handshake sent ${handshake}`);
			await writer.write(handshake);
			await sleep(100);
			// 2.receive
			const status = await new Promise(async (resolve) => {
				while (true) {
					const packet = (await reader.read()) as ReadableStreamReadResult<Uint8Array>;
					let buf = packet.value;
					if (buf == undefined) {
						continue;
					}
					console.log(`handshake receive ${buf}`);

					const dataLen = readVarInt(buf);
					buf = dataLen.data;
					const packetId = readVarInt(buf);
					buf = packetId.data;
					const statusLen = readVarInt(buf);
					buf = statusLen.data;
					const statusRaw = new TextDecoder().decode(buf);
					const status = JSON.parse(statusRaw);
					resolve(status);
				}
			});

			await socket.close();
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

function readVarInt(data: Uint8Array): readResult<number> {
	let position = 0;
	let length = 0;
	let value = 0;

	while (true) {
		length++;
		const current = data[position];
		value = value | (current & (segmentBit << position));
		if ((current & continueBit) == 0) {
			break;
		}
		position += 7;
		if (position > 32) {
			break;
		}
	}
	return {
		data: data.slice(length),
		dataLength: length,
		value: value,
	};
}

function handshakePacket(): Uint8Array {
	let data = new Uint8Array();

	const packetId = writeVarInt(0);
	data = concatUint8Array(data, packetId);
	const protocolVer = writeVarInt(3);
	data = concatUint8Array(data, protocolVer);
	const address = new TextEncoder().encode('mc-status.example.com');
	const addressLen = writeVarInt(address.length);
	data = concatUint8Array(data, addressLen);
	data = concatUint8Array(data, address);
	const port = new Uint8Array(2);
	new DataView(port.buffer).setUint16(0, 25565);
	data = concatUint8Array(data, port);
	const next = writeVarInt(1);
	data = concatUint8Array(data, next);
	const length = writeVarInt(data.length);

	let packet = new Uint8Array();
	packet = concatUint8Array(packet, length);
	packet = concatUint8Array(packet, data);
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
	return new Promise((resolve) => setTimeout(resolve, 1000));
}
