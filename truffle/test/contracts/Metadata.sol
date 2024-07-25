pragma solidity ^0.5.0;

contract Metadata {
    struct MetadataStruct {
        string deviceId;
        string macAddress;
        string firmwareVersion;
        string publicKey;
        string privateKey;
        string contractAddress;
    }

    mapping(uint => MetadataStruct) public metadata;

    uint public metadataCount;

    function addMetadata(
        string memory deviceId,
        string memory macAddress,
        string memory firmwareVersion,
        string memory publicKey,
        string memory privateKey,
        string memory contractAddress
    )
        public
    {
        metadata[metadataCount] = MetadataStruct(deviceId, macAddress, firmwareVersion, publicKey, privateKey, contractAddress);
        metadataCount++;
    }

    function getMetadata(uint index) public view returns (
        string memory deviceId,
        string memory macAddress,
        string memory firmwareVersion,
        string memory publicKey,
        string memory privateKey,
        string memory contractAddress
    ) {
        MetadataStruct memory data = metadata[index];
        return (
            data.deviceId,
            data.macAddress,
            data.firmwareVersion,
            data.publicKey,
            data.privateKey,
            data.contractAddress
        );
    }
}