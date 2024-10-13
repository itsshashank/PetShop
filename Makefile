ipfs-build:
	docker build custom-ipfs -t custom-ipfs

ipfs-up:
	docker run -d -v data:/data/ipfs --name ipfs-node -p 4001:4001 -p 5001:5001 -p 8081:8080 custom-ipfs

ipfs-down:
	docker stop ipfs-node
	docker rm ipfs-node
