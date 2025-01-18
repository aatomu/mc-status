/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.json`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { connect } from 'cloudflare:sockets';

const segmentBit = 0x7f;
const continueBit = 0x80;

interface result {
	message: string;
	data: any;
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
				message: 'address params not found.',
			} as result);
		}
		const port = params.get('port') || '25565';

		// dial tcp
		const addr = { hostname: address, port: Number(port) };
		const socket = connect(addr);
		const writer = socket.writable.getWriter();
		const reader = socket.readable.getReader();

		// handshake packet
		// 1.sent
		const handshake = handshakePacket();
		console.log(`handshake sent ${handshake}`);
		await writer.write(handshake);
		await new Promise((resolve) => setTimeout(resolve, 1000));
		// 2.receive
		while (true) {
			const packet = (await reader.read()) as ReadableStreamReadResult<Uint8Array>;
			let buf = packet.value;
			if (buf == undefined) {
				continue;
			}
			console.log(`handshake receive ${buf}`);

			const dataLen = readVarInt(buf);
			buf = dataLen.data
			const packetId = readVarInt(buf);
			buf = packetId.data
			const statusLen = readVarInt(buf);
			buf = statusLen.data
			const statusRaw = new TextDecoder().decode(buf)
			console.log("raw",statusRaw)
			const status = JSON.parse(statusRaw)
			console.log("parsed",status)
			break
		}
		return new Response(`${address}:${port} connected`);
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
