// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PetShop {
    struct Item {
        string name;
        string description;
        string ipfsUrl;
        uint256 price;
        uint256 quantity;
        address payable owner;
        bool isPet; // To distinguish between pets and products
        bool isSold; // To indicate if the pet is sold
    }

    Item[] public items;

    function listItem(
        string memory _name, 
        string memory _description, 
        uint256 _price, 
        uint256 _quantity, 
        string memory _ipfsUrl, 
        bool _isPet
    ) public {
        items.push(Item({
            name: _name,
            description: _description,
            ipfsUrl: _ipfsUrl,
            price: _price,
            quantity: _quantity,
            owner: payable(msg.sender),
            isPet: _isPet,
            isSold: false
        }));
    }

    function getAvailablePets() public view returns (uint256[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < items.length; i++) {
            if (items[i].isPet && !items[i].isSold) {
                count++;
            }
        }

        uint256[] memory result = new uint256[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < items.length; i++) {
            if (items[i].isPet && !items[i].isSold) {
                result[index] = i;
                index++;
            }
        }

        return result;
    }

    function getAvailableProducts() public view returns (uint256[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < items.length; i++) {
            if (!items[i].isPet && items[i].quantity > 0) {
                count++;
            }
        }

        uint256[] memory result = new uint256[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < items.length; i++) {
            if (!items[i].isPet && items[i].quantity > 0) {
                result[index] = i;
                index++;
            }
        }

        return result;
    }

    function getItem(uint256 index) public view returns (string memory, string memory, uint256, string memory, address, uint256, uint256) {
        require(index < items.length, "Invalid index");
        Item memory item = items[index];
        return (item.name, item.description, item.price, item.ipfsUrl, item.owner, index, item.quantity);
    }


    function getMyPets() public view returns (uint256[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < items.length; i++) {
            if (items[i].isPet && items[i].owner == msg.sender) {
                count++;
            }
        }

        uint256[] memory result = new uint256[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < items.length; i++) {
            if (items[i].isPet && items[i].owner == msg.sender) {
                result[index] = i;
                index++;
            }
        }

        return result;
    }

    function buyPet(uint256 _petId) public payable {
        Item storage pet = items[_petId];
        
        require(msg.value >= pet.price, "Insufficient funds sent");
        require(pet.owner != msg.sender, "You already own this pet");

        pet.owner.transfer(pet.price);
        pet.isSold = true;
        pet.owner = payable(msg.sender);
    }

    struct Order {
        bytes32 orderId;  // UUID-like identifier
        string ipfsUrl;
        string productName;
        uint256 quantity;
        uint256 totalPrice;
        address buyer;
        uint256 timestamp;
    }

    mapping(address => Order[]) public orderHistory;

    function buyProduct(uint256 _productId, uint256 _quantity) public payable {
        Item storage product = items[_productId];

        require(!product.isPet, "This item is a pet, use buyPet function.");
        require(product.quantity >= _quantity, "Not enough quantity available.");
        uint256 totalPrice = product.price * _quantity;
        require(msg.value >= totalPrice, "Insufficient funds sent.");

        (bool success, ) = product.owner.call{value: totalPrice}("");
        require(success, "Transfer failed.");

        product.quantity -= _quantity;

        bytes32 newOrderId = keccak256(
            abi.encodePacked(block.timestamp, msg.sender, _productId, _quantity)
        );

        // Add to order history
        orderHistory[msg.sender].push(Order({
            orderId: newOrderId,
            ipfsUrl: product.ipfsUrl,
            productName: product.name,
            quantity: _quantity,
            totalPrice: totalPrice,
            buyer: msg.sender,
            timestamp: block.timestamp
        }));
    }

    function getOrderHistory() public view returns (Order[] memory) {
        return orderHistory[msg.sender];
    }
}
