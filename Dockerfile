# 使用官方 Bun 镜像作为基础镜像
FROM oven/bun:1-alpine

# 设置工作目录
WORKDIR /app

# 复制项目文件
COPY package.json ./
COPY index.js ./
COPY worker.js ./

# 暴露端口 (云平台通常通过环境变量覆盖，但默认为 3000)
EXPOSE 3000

# 启动服务
CMD ["bun", "run", "start"]
