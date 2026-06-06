// 常量配置
const PPV_STREAMS = 'https://api.ppv.to/api/streams';
const POO_FETCH = 'https://pooembed.eu/fetch';
const POO_ORIGIN = 'https://pooembed.eu';
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36';
const DEFAULT_ID = 'rally-tv';
const ROOM_TTL = 600;
const SOURCE_TTL = 300;
const TOKEN_MARGIN = 90;

// 分组名称中英对照翻译字典 (自动拼接 PPV- 前缀)
const GROUP_TRANSLATIONS = {
    "American Football": "PPV-美式橄榄球",
    "Arm Wrestling": "PPV-腕力运动",
    "Australian Football": "PPV-澳式橄榄球",
    "Baseball": "PPV-棒球",
    "Basketball": "PPV-篮球",
    "Combat Sports": "PPV-格斗搏击",
    "Cricket": "PPV-板球",
    "Football": "PPV-足球",
    "Motorsports": "PPV-赛车运动",
    "Rugby": "PPV-英式橄榄球",
    "Tennis": "PPV-网球",
    "Wrestling": "PPV-职业摔角",
    "24/7 Streams": "PPV-24/7轮播"
};

// 全局内存缓存，防止跨节点频繁请求触发风控
const globalCache = new Map();

function cache_get(kind, key) {
    const cacheKey = `${kind}:${key}`;
    const hit = globalCache.get(cacheKey);
    if (!hit) return null;
    if (hit.until <= Math.floor(Date.now() / 1000)) {
        globalCache.delete(cacheKey);
        return null;
    }
    return hit.data;
}

function cache_set(kind, key, data, until) {
    if (until <= Math.floor(Date.now() / 1000)) return;
    const cacheKey = `${kind}:${key}`;
    globalCache.set(cacheKey, { data, until });
}

// 基础类型与编码转换工具
const stringToBytes = str => new TextEncoder().encode(str);
const bytesToString = bytes => new TextDecoder().decode(bytes);

function shift_payload(s) {
    let o = '';
    for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);
        if (c >= 33 && c <= 126) {
            o += String.fromCharCode(((c - 33 + 71) % 94) + 33);
        } else {
            o += s[i];
        }
    }
    return o;
}

// Protobuf / Varint 编解码
function enc_varint(n) {
    let res = [];
    while (true) {
        let b = n & 0x7f;
        n >>>= 7;
        if (n === 0) {
            res.push(b);
            break;
        }
        res.push(b | 0x80);
    }
    return new Uint8Array(res);
}

function pb_put(field, value) {
    let valBytes = typeof value === 'string' ? stringToBytes(value) : value;
    let tag = enc_varint((field << 3) | 2);
    let len = enc_varint(valBytes.length);
    let out = new Uint8Array(tag.length + len.length + valBytes.length);
    out.set(tag, 0);
    out.set(len, tag.length);
    out.set(valBytes, tag.length + len.length);
    return out;
}

function get_varint(bytes, state) {
    let n = 0;
    let shift = 0;
    while (state.i < bytes.length) {
        let b = bytes[state.i++];
        n |= (b & 0x7f) << shift;
        if (b < 0x80) {
            return n >>> 0;
        }
        shift += 7;
        if (shift > 63) throw new Error('bad varint');
    }
    throw new Error('short varint');
}

function pb_read(bytes) {
    let state = { i: 0 };
    let out = {};
    while (state.i < bytes.length) {
        let tag = get_varint(bytes, state);
        let field = tag >> 3;
        let wire = tag & 7;
        if (wire !== 2) throw new Error('bad wire');
        let n = get_varint(bytes, state);
        if (state.i + n > bytes.length) throw new Error('short field');
        out[field] = bytes.subarray(state.i, state.i + n);
        state.i += n;
    }
    return out;
}

// ChaCha20 加解密算法实现
function le32(bytes, i) {
    return (bytes[i] | (bytes[i+1] << 8) | (bytes[i+2] << 16) | (bytes[i+3] << 24)) >>> 0;
}

function put32(n, bytes, i) {
    bytes[i] = n & 0xff;
    bytes[i+1] = (n >>> 8) & 0xff;
    bytes[i+2] = (n >>> 16) & 0xff;
    bytes[i+3] = (n >>> 24) & 0xff;
}

function chacha_qr(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0;
    let t1 = x[d] ^ x[a]; x[d] = ((t1 << 16) | (t1 >>> 16)) >>> 0;
    x[c] = (x[c] + x[d]) >>> 0;
    let t2 = x[b] ^ x[c]; x[b] = ((t2 << 12) | (t2 >>> 20)) >>> 0;
    x[a] = (x[a] + x[b]) >>> 0;
    let t3 = x[d] ^ x[a]; x[d] = ((t3 << 8) | (t3 >>> 24)) >>> 0;
    x[c] = (x[c] + x[d]) >>> 0;
    let t4 = x[b] ^ x[c]; x[b] = ((t4 << 7) | (t4 >>> 25)) >>> 0;
}

const CHACHA_CONST = stringToBytes('expand 32-byte k');
function chacha_block(key, nonce, counter) {
    let s = new Uint32Array(16);
    s[0] = le32(CHACHA_CONST, 0); s[1] = le32(CHACHA_CONST, 4);
    s[2] = le32(CHACHA_CONST, 8); s[3] = le32(CHACHA_CONST, 12);
    s[4] = le32(key, 0);  s[5] = le32(key, 4);  s[6] = le32(key, 8);  s[7] = le32(key, 12);
    s[8] = le32(key, 16); s[9] = le32(key, 20); s[10] = le32(key, 24); s[11] = le32(key, 28);
    s[12] = counter >>> 0;
    s[13] = le32(nonce, 0); s[14] = le32(nonce, 4); s[15] = le32(nonce, 8);
    
    let x = new Uint32Array(s);
    for (let i = 0; i < 10; i++) {
        chacha_qr(x, 0, 4, 8, 12);
        chacha_qr(x, 1, 5, 9, 13);
        chacha_qr(x, 2, 6, 10, 14);
        chacha_qr(x, 3, 7, 11, 15);
        chacha_qr(x, 0, 5, 10, 15);
        chacha_qr(x, 1, 6, 11, 12);
        chacha_qr(x, 2, 7, 8, 13);
        chacha_qr(x, 3, 4, 9, 14);
    }
    let out = new Uint8Array(64);
    for (let i = 0; i < 16; i++) {
        put32((x[i] + s[i]) >>> 0, out, i * 4);
    }
    return out;
}

function chacha_stream(key, nonce, len, counter) {
    let out = new Uint8Array(Math.ceil(len / 64) * 64);
    let idx = 0;
    while (idx < len) {
        let block = chacha_block(key, nonce, counter);
        out.set(block, idx);
        counter = (counter + 1) >>> 0;
        idx += 64;
    }
    return out.subarray(0, len);
}

// Poly1305 签名逻辑
function poly1305_mac(msg, key) {
    let t0 = BigInt(le32(key, 0)); let t1 = BigInt(le32(key, 4));
    let t2 = BigInt(le32(key, 8)); let t3 = BigInt(le32(key, 12));
    let r0 = t0 & 0x3ffffffn;
    let r1 = ((t0 >> 26n) | (t1 << 6n)) & 0x3ffff03n;
    let r2 = ((t1 >> 20n) | (t2 << 12n)) & 0x3ffc0ffn;
    let r3 = ((t2 >> 14n) | (t3 << 18n)) & 0x3f03fffn;
    let r4 = (t3 >> 8n) & 0x00fffffn;
    let s1 = r1 * 5n; let s2 = r2 * 5n; let s3 = r3 * 5n; let s4 = r4 * 5n;
    let h0 = 0n, h1 = 0n, h2 = 0n, h3 = 0n, h4 = 0n;
    let mask = 0x3ffffffn; let len = msg.length;
    for (let pos = 0; pos < len; pos += 16) {
        let n = Math.min(16, len - pos);
        let block = new Uint8Array(16);
        block.set(msg.subarray(pos, pos + n), 0);
        let hibit = 1n << 24n;
        if (n < 16) { block[n] = 0x01; hibit = 0n; }
        let bt0 = BigInt(le32(block, 0)); let bt1 = BigInt(le32(block, 4));
        let bt2 = BigInt(le32(block, 8)); let bt3 = BigInt(le32(block, 12));
        h0 += bt0 & mask;
        h1 += ((bt0 >> 26n) | (bt1 << 6n)) & mask;
        h2 += ((bt1 >> 20n) | (bt2 << 12n)) & mask;
        h3 += ((bt2 >> 14n) | (bt3 << 18n)) & mask;
        h4 += ((bt3 >> 8n) & 0x00ffffffn) | hibit;
        let d0 = (h0 * r0) + (h1 * s4) + (h2 * s3) + (h3 * s2) + (h4 * s1);
        let d1 = (h0 * r1) + (h1 * r0) + (h2 * s4) + (h3 * s3) + (h4 * s2);
        let d2 = (h0 * r2) + (h1 * r1) + (h2 * r0) + (h3 * s4) + (h4 * s3);
        let d3 = (h0 * r3) + (h1 * r2) + (h2 * r1) + (h3 * r0) + (h4 * s4);
        let d4 = (h0 * r4) + (h1 * r3) + (h2 * r2) + (h3 * r1) + (h4 * r0);
        let c = d0 >> 26n; h0 = d0 & mask; d1 += c;
        c = d1 >> 26n; h1 = d1 & mask; d2 += c;
        c = d2 >> 26n; h2 = d2 & mask; d3 += c;
        c = d3 >> 26n; h3 = d3 & mask; d4 += c;
        c = d4 >> 26n; h4 = d4 & mask; h0 += c * 5n;
        c = h0 >> 26n; h0 &= mask; h1 += c;
    }
    let c = h1 >> 26n; h1 &= mask; h2 += c; c = h2 >> 26n; h2 &= mask;
    h3 += c; c = h3 >> 26n; h3 &= mask; h4 += c; c = h4 >> 26n; h4 &= mask;
    h0 += c * 5n; c = h0 >> 26n; h0 &= mask; h1 += c;
    let g0 = h0 + 5n; c = g0 >> 26n; g0 &= mask;
    let g1 = h1 + c; c = g1 >> 26n; g1 &= mask;
    let g2 = h2 + c; c = g2 >> 26n; g2 &= mask;
    let g3 = h3 + c; c = g3 >> 26n; g3 &= mask;
    let g4 = h4 + c - (1n << 26n);
    if (g4 >= 0n) { h0 = g0; h1 = g1; h2 = g2; h3 = g3; h4 = g4; }
    let f0 = ((h0 | (h1 << 26n)) & 0xffffffffn) + BigInt(le32(key, 16));
    let w0 = f0 & 0xffffffffn;
    let f1 = (((h1 >> 6n) | (h2 << 20n)) & 0xffffffffn) + BigInt(le32(key, 20)) + (f0 >> 32n);
    let w1 = f1 & 0xffffffffn;
    let f2 = (((h2 >> 12n) | (h3 << 14n)) & 0xffffffffn) + BigInt(le32(key, 24)) + (f1 >> 32n);
    let w2 = f2 & 0xffffffffn;
    let f3 = (((h3 >> 18n) | (h4 << 8n)) & 0xffffffffn) + BigInt(le32(key, 28)) + (f2 >> 32n);
    let w3 = f3 & 0xffffffffn;
    let out = new Uint8Array(16);
    put32(Number(w0), out, 0); put32(Number(w1), out, 4);
    put32(Number(w2), out, 8); put32(Number(w3), out, 12);
    return out;
}

function le64(n) {
    let out = new Uint8Array(8);
    put32(n % 4294967296, out, 0);
    put32(Math.floor(n / 4294967296), out, 4);
    return out;
}

function pad16(bytes) {
    let n = bytes.length % 16;
    return n === 0 ? new Uint8Array(0) : new Uint8Array(16 - n);
}

function aead_input(aad, ciphertext) {
    let pAad = pad16(aad); let pCipher = pad16(ciphertext);
    let lAad = le64(aad.length); let lCipher = le64(ciphertext.length);
    let out = new Uint8Array(aad.length + pAad.length + ciphertext.length + pCipher.length + 16);
    let o = 0;
    out.set(aad, o); o += aad.length; out.set(pAad, o); o += pAad.length;
    out.set(ciphertext, o); o += ciphertext.length; out.set(pCipher, o); o += pCipher.length;
    out.set(lAad, o); o += 8; out.set(lCipher, o);
    return out;
}

function bxor_stream(a, b) {
    let out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
}

function hash_equals(a, b) {
    if (a.length !== b.length) return false;
    let c = 0;
    for (let i = 0; i < a.length; i++) c |= a[i] ^ b[i];
    return c === 0;
}

function open_payload(payloadStr, islandStr) {
    let shifted = shift_payload(payloadStr);
    let binaryString = atob(shifted);
    let packed = Uint8Array.from(binaryString, c => c.charCodeAt(0));
    if (packed.length < 28) throw new Error('bad payload');
    
    let nonce = packed.subarray(0, 12);
    let box = packed.subarray(12);
    let islandBytes = stringToBytes(islandStr);
    let key = new Uint8Array(32);
    key.set(islandBytes.subarray(0, Math.min(32, islandBytes.length)), 0);
    
    let tag = box.subarray(box.length - 16);
    let ciphertext = box.subarray(0, box.length - 16);
    
    let poly_key = chacha_stream(key, nonce, 32, 0);
    let got = poly1305_mac(aead_input(new Uint8Array(0), ciphertext), poly_key);
    if (!hash_equals(got, tag)) throw new Error('bad tag');
    
    let decrypted = bxor_stream(ciphertext, chacha_stream(key, nonce, ciphertext.length, 1));
    return bytesToString(decrypted);
}

// 修改后的 HTTP 网络请求核心包装 (增加防风控 Headers 和详细溯源日志)
async function http_call(url, method = 'GET', body = null, headers = {}) {
    let options = {
        method: method,
        headers: { 
            'User-Agent': BROWSER_UA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            ...headers 
        },
        redirect: 'follow'
    };
    if (method !== 'GET') options.body = body;
    let res = await fetch(url, options);
    
    if (!res.ok) {
        throw new Error(`http ${res.status} on URL: ${url}`);
    }
    
    let bag = {};
    for (let [k, v] of res.headers.entries()) bag[k.toLowerCase()] = v;
    
    let buffer = await res.arrayBuffer();
    return [new Uint8Array(buffer), bag, res.status];
}

// 房间与流逻辑处理
async function room_slug(id) {
    let hit = cache_get('room', id);
    if (hit) return hit;
    
    let [bin] = await http_call(PPV_STREAMS);
    let data = JSON.parse(bytesToString(bin));
    let want = id.replace(/^ppv-/, '').trim();
    for (let cat of (data.streams || [])) {
        for (let item of (cat.streams || [])) {
            let num = item.id ? String(item.id) : '';
            if (num === want || ('ppv-' + num) === id || item.uri_name === id) {
                let slug = String(item.uri_name || '').trim();
                if (slug !== '') {
                    cache_set('room', id, slug, Math.floor(Date.now() / 1000) + ROOM_TTL);
                    return slug;
                }
            }
        }
    }
    throw new Error('room not found');
}

// ==========================================
// 获取并展平所有频道的辅助函数（含中文化分组逻辑）
// ==========================================
async function get_all_streams_list() {
    let [bin] = await http_call(PPV_STREAMS);
    let data = JSON.parse(bytesToString(bin));
    let results = [];

    for (let cat of (data.streams || [])) {
        let rawCategory = cat.category || "Uncategorized";
        let groupName = GROUP_TRANSLATIONS[rawCategory] || `PPV-${rawCategory}`;
        
        for (let item of (cat.streams || [])) {
            if (item.uri_name) {
                results.push({
                    name: item.name + (item.source_tag ? ` [${item.source_tag}]` : ''),
                    group: groupName,
                    logo: item.poster || "",
                    id: item.uri_name
                });
            }
            for (let sub of (item.substreams || [])) {
                if (sub.uri_name) {
                    results.push({
                        name: sub.name + (sub.source_tag ? ` [${sub.source_tag}]` : ''),
                        group: groupName,
                        logo: item.poster || "",
                        id: sub.uri_name
                    });
                }
            }
        }
    }
    return results;
}

async function fresh_url(slug) {
    let body = pb_put(1, slug);
    let [bin, headers] = await http_call(POO_FETCH, 'POST', body, {
        'Content-Type': 'application/octet-stream',
        'Origin': POO_ORIGIN,
        'Referer': POO_ORIGIN + '/embed/' + encodeURIComponent(slug),
        'Accept': '*/*'
    });
    let island = headers['island'] || '';
    if (!island) throw new Error('no island');
    let fields = pb_read(bin);
    if (!fields[1]) throw new Error('no payload');
    
    return open_payload(bytesToString(fields[1]), island);
}

async function hls_get(url, slug) {
    let [bin] = await http_call(url, 'GET', null, {
        'Origin': POO_ORIGIN,
        'Referer': POO_ORIGIN + '/embed/' + encodeURIComponent(slug),
        'Accept': '*/*'
    });
    let text = bytesToString(bin);
    if (!text.trim().startsWith('#EXTM3U')) throw new Error('not m3u8');
    return text;
}

function url_join(base, ref) {
    try { return new URL(ref, base).href; } catch (e) { return ref; }
}

function maybe_m3u8(uri) {
    try {
        return new URL(uri, 'http://a.com').pathname.toLowerCase().includes('.m3u8');
    } catch(e) {
        return uri.toLowerCase().includes('.m3u8');
    }
}

function stream_score(line) {
    let score = 0;
    let m1 = line.match(/BANDWIDTH=(\d+)/); if (m1) score += parseInt(m1[1], 10);
    let m2 = line.match(/RESOLUTION=(\d+)x(\d+)/); if (m2) score += parseInt(m2[1], 10) * parseInt(m2[2], 10) * 10;
    return score;
}

function m3u8_refs(text, base) {
    let refs = []; let pending = 0;
    let lines = text.replace(/\r\n|\r/g, '\n').split('\n');
    for (let line of lines) {
        let trim = line.trim(); if (trim === '') continue;
        if (trim.startsWith('#')) {
            if (trim.startsWith('#EXT-X-STREAM-INF')) pending = stream_score(trim);
            if (line.includes('URI="')) {
                let hits = line.matchAll(/URI="([^"]+)"/g);
                for (let hit of hits) {
                    if (maybe_m3u8(hit[1])) {
                        refs.push({ url: url_join(base, hit[1]), rank: trim.includes('I-FRAME') ? 0 : 1, score: stream_score(trim) });
                    }
                }
            }
            continue;
        }
        if (maybe_m3u8(trim)) refs.push({ url: url_join(base, trim), rank: pending > 0 ? 3 : 2, score: pending });
        pending = 0;
    }
    refs.sort((a, b) => (b.rank - a.rank) || (b.score - a.score));
    return refs;
}

async function final_m3u8(url, slug) {
    let seen = new Set();
    for (let i = 0; i < 8; i++) {
        if (seen.has(url)) throw new Error('m3u8 loop');
        seen.add(url);
        let text = await hls_get(url, slug);
        let refs = m3u8_refs(text, url);
        if (refs.length === 0) return [text, url];
        url = refs[0].url;
    }
    throw new Error('m3u8 too deep');
}

function secure_until(url) {
    try {
        let parts = new URL(url).pathname.split('/');
        for (let i = 0; i < parts.length; i++) {
            if (parts[i] === 'secure' && parts[i+3] && /^\d+$/.test(parts[i+3])) {
                return parseInt(parts[i+3], 10) - TOKEN_MARGIN;
            }
        }
    } catch (e) {}
    return null;
}

function source_until(source, final) {
    let now = Math.floor(Date.now() / 1000);
    let until = now + SOURCE_TTL;
    for (let url of [source, final]) {
        let end = secure_until(url);
        if (end !== null) until = Math.min(until, end);
    }
    return Math.max(now + 20, until);
}

async function live_m3u8(slug) {
    let hit = cache_get('source', slug);
    if (hit && hit.final) {
        try {
            let text = await hls_get(hit.final, slug);
            if (m3u8_refs(text, hit.final).length === 0) return [text, hit.final, 'HIT'];
        } catch (e) {}
    }
    let source = await fresh_url(slug);
    let [text, final] = await final_m3u8(source, slug);
    cache_set('source', slug, { source, final }, source_until(source, final));
    return [text, final, 'MISS'];
}

// 核心反断流机制：将所有内部资源链接强行重写重定向回此 Worker 代理路由
function abs_m3u8(text, base, workerHost, slug) {
    let lines = text.replace(/\r\n|\r/g, '\n').split('\n');
    let out = [];
    for (let line of lines) {
        let trim = line.trim();
        if (trim === '') {
            out.push(line);
        } else if (trim.startsWith('#')) {
            if (line.includes('URI="')) {
                let newLine = line.replace(/URI="([^"]+)"/g, (m, g1) => {
                    let absUrl = url_join(base, g1);
                    return `URI="${workerHost}/proxy?slug=${encodeURIComponent(slug)}&url=${encodeURIComponent(absUrl)}"`;
                });
                out.push(newLine);
            } else {
                out.push(line);
            }
        } else {
            let absUrl = url_join(base, trim);
            out.push(`${workerHost}/proxy?slug=${encodeURIComponent(slug)}&url=${encodeURIComponent(absUrl)}`);
        }
    }
    return out.join('\n') + '\n';
}

// Fetch 触发器主入口
export default {
    async fetch(request, env, ctx) {
        const urlObj = new URL(request.url);
        const workerHost = urlObj.origin;
        const pathname = urlObj.pathname;
        
        // --- 1. 核心反断流机制：流式转发和头部伪造子路由 ---
        if (pathname === '/proxy') {
            const targetUrl = urlObj.searchParams.get('url');
            const slug = urlObj.searchParams.get('slug') || '';
            if (!targetUrl) return new Response('Missing target url', { status: 400 });
            
            try {
                // 伪造完整的浏览器级播放请求上下文请求头
                let response = await fetch(targetUrl, {
                    method: 'GET',
                    headers: {
                        'User-Agent': BROWSER_UA,
                        'Origin': POO_ORIGIN,
                        'Referer': `${POO_ORIGIN}/embed/${encodeURIComponent(slug)}`,
                        'Accept': '*/*'
                    }
                });
                
                if (!response.ok) return new Response(`Proxy error: ${response.status}`, { status: response.status });
                const contentType = response.headers.get('content-type') || '';
                
                // 如果是嵌套二级 M3U8 列表，同样重写它的行内容
                if (contentType.includes('mpegurl') || contentType.includes('m3u8') || targetUrl.includes('.m3u8')) {
                    let text = await response.text();
                    let rewrittenM3u8 = abs_m3u8(text, targetUrl, workerHost, slug);
                    return new Response(rewrittenM3u8, {
                        headers: {
                            'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8',
                            'Cache-Control': 'no-store',
                            'Access-Control-Allow-Origin': '*'
                        }
                    });
                }
                
                // 如果是切片数据 (.ts / .m4s / .mp4)，直接秒级流式边下边传
                return new Response(response.body, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: {
                        'Content-Type': contentType,
                        'Cache-Control': response.headers.get('cache-control') || 'public, max-age=3600',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            } catch (e) {
                return new Response(e.message, { status: 502 });
            }
        }

        // --- 2. 导出全部频道的 M3U 订阅源 ---
        if (pathname === '/m3u') {
            try {
                const streams = await get_all_streams_list();
                let m3u8 = "#EXTM3U\n";
                for (let s of streams) {
                    m3u8 += `#EXTINF:-1 tvg-logo="${s.logo}" group-title="${s.group}",${s.name}\n`;
                    m3u8 += `${workerHost}/?id=${encodeURIComponent(s.id)}\n`;
                }
                return new Response(m3u8, {
                    headers: {
                        'Content-Type': 'audio/x-mpegurl; charset=utf-8',
                        'Content-Disposition': 'inline; filename="playlist.m3u"',
                        'Cache-Control': 'no-store',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            } catch (e) {
                return new Response(`Error fetching streams: ${e.message}`, { status: 502 });
            }
        }

        // --- 3. 导出全部频道的 TXT 订阅源 ---
        if (pathname === '/txt') {
            try {
                const streams = await get_all_streams_list();
                let txt = "";
                let currentGroup = "";
                for (let s of streams) {
                    if (currentGroup !== s.group) {
                        txt += `${s.group},#genre#\n`;
                        currentGroup = s.group;
                    }
                    txt += `${s.name},${workerHost}/?id=${encodeURIComponent(s.id)}\n`;
                }
                return new Response(txt, {
                    headers: {
                        'Content-Type': 'text/plain; charset=utf-8',
                        'Content-Disposition': 'inline; filename="playlist.txt"',
                        'Cache-Control': 'no-store',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            } catch (e) {
                return new Response(`Error fetching streams: ${e.message}`, { status: 502 });
            }
        }
        
        // --- 4. 主路由：获取指定频道的主 M3U8 索引 ---
        let id = urlObj.searchParams.get('id') || DEFAULT_ID;
        id = id.trim() === '' ? DEFAULT_ID : id;
        
        try {
            const slug = await room_slug(id);
            const [m3u8, base, cacheStatus] = await live_m3u8(slug);
            
            // 生成动态重写之后的反断流 M3U8 文本
            const dynamicM3u8 = abs_m3u8(m3u8, base, workerHost, slug);
            
            return new Response(dynamicM3u8, {
                headers: {
                    'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8',
                    'Cache-Control': 'no-store',
                    'X-PPV-Cache': cacheStatus,
                    'Access-Control-Allow-Origin': '*'
                }
            });
        } catch (e) {
            return new Response(e.message, {
                status: 502,
                headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
        }
    }
};
