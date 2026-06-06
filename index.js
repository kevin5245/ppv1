import worker from './worker.js';

const port = process.env.PORT || 3000;
console.log(`🚀 Server is running on port ${port}...`);

export default {
    port: port,
    // 拦截原生的请求，原样传递给你的 Worker 脚本
    async fetch(request) {
        try {
            // 模拟 Cloudflare 的 env 和 ctx (提供空白对象避免报错)
            const env = process.env;
            const ctx = {
                waitUntil: () => {},
                passThroughOnException: () => {}
            };
            
            return await worker.fetch(request, env, ctx);
        } catch (error) {
            console.error("Server Error:", error);
            return new Response(`Internal Server Error: ${error.message}`, { status: 500 });
        }
    }
};
