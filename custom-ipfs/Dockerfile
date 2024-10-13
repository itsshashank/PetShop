# Use the official IPFS image as the base image
FROM ipfs/go-ipfs:latest

# Set environment variables (optional if you use config in entrypoint.sh)
ENV IPFS_API_HTTP_HEADERS='{"Access-Control-Allow-Origin":["*"],"Access-Control-Allow-Methods":["PUT","POST","GET"],"Access-Control-Allow-Credentials":["true"]}'

# Expose the necessary ports
EXPOSE 4001 5001 8080

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Use the custom entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
