pragma solidity ^0.4.2;

/**
 @title Open Domain Name System Contract
 @author Harsh Vakharia <harshjv@gmail.com> (https://harshjv.github.io)
 */
contract OpenDomainNameSystem {
  enum RecordType { A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, NAPTR, OPT, SPF, TLSA }
  uint constant totalRecordTypes = uint(RecordType.TLSA) + 1;

  // domain => owner
  mapping(string => address) domainToOwner;
  // owner => array(domain)
  mapping(address => string[]) ownerToDomains;
  // domain => (recordType => json(record))
  mapping(string => mapping(uint => string)) domainToRecords;
  // domain => index of domain in ownerToDomains(owner)
  mapping(string => uint) domainToOwnerArrayIndex;
  // domain => json(whois)
  mapping(string => string) domainToWhois;
  // domain => created timestamp
  mapping(string => uint) domainToCreated;
  // domain => updated timestamp
  mapping(string => uint) domainToUpdated;

  /**
   @notice OpenDomainNameSystem Constructor
   */
  function OpenDomainNameSystem () {}

  modifier domainShouldNotExist (string domain) {
    if (domainToOwner[domain] != address(0x0)) throw;
    _;
  }

  modifier domainShouldExist (string domain) {
    if (domainToOwner[domain] == address(0x0)) throw;
    _;
  }

  modifier onlyByOwner (string domain) {
    address sender = msg.sender;
    address owner = domainToOwner[domain];

    if (owner != sender) throw;
    _;
  }

  modifier domainUpdated (string domain) {
    _;
    domainToUpdated[domain] = now;
  }

  modifier domainCreated (string domain) {
    _;
    domainToCreated[domain] = now;
  }

  modifier addressShouldBeDifferentThanSender (address addr) {
    address sender = msg.sender;

    if (sender == addr) throw;
    _;
  }

  /**
   @notice Register domain name
   @param domain Domain name to be registered
   @param whois JSON-encoded WHOIS information
   */
  function registerDomain (string domain, string whois)
                           domainShouldNotExist(domain)
                           domainCreated(domain)
                           domainUpdated(domain) {
  	address owner = msg.sender;

    setDomainOwner(domain, owner);

    domainToWhois[domain] = whois;
  }

  /**
   @notice Transfer registered domain name to a different ether address
   @param domain Domain name to be transfered
   @param newOwner Ether address of the new owner
   @param whois JSON-encoded WHOIS information
   */
  function transferDomain (string domain, address newOwner, string whois)
                           domainShouldExist(domain)
                           onlyByOwner(domain)
                           addressShouldBeDifferentThanSender(newOwner)
                           domainUpdated(domain) {
    address oldOwner = msg.sender;

    removeDomainOwner(domain, oldOwner);
    removeAllRecordsOfDomain(domain);
    setDomainOwner(domain, newOwner);

    domainToWhois[domain] = whois;
  }

  /**
   @notice Set WHOIS data of a registered domain
   @param domain Domain name
   @param whois JSON-encoded WHOIS information
   */
  function setWhoisData (string domain, string whois)
                         domainShouldExist(domain)
                         onlyByOwner(domain)
                         domainUpdated(domain) {
    domainToWhois[domain] = whois;
  }

  /**
   @notice Get WHOIS data of a registered domain
   @param domain Domain name
   @return {
     "owner" : "Ether address of domain owner",
     "whois": "JSON-encoded WHOIS data",
     "created": "Created-at timestamp",
     "updated": "Updated-at timestamp"
   }
   */
  function getWhoisData (string domain)
                        domainShouldExist(domain)
                        constant returns (address owner, string whois,
                                          uint created, uint updated) {
    owner = domainToOwner[domain];
    whois = domainToWhois[domain];
    created = domainToCreated[domain];
    updated = domainToUpdated[domain];

    return (owner, whois, created, updated);
  }

  /**
   @notice Set DNS record of a registered domain
   @param domain Domain name
   @param recordType Record type from RecordType enum data type
   @param data JSON-encoded record data
   */
  function setRecord (string domain, RecordType recordType, string data)
                         domainShouldExist(domain)
                         onlyByOwner(domain) {
    domainToRecords[domain][uint(recordType)] = data;
  }

  /**
   @notice Get DNS record of a registered domain
   @param domain Domain name
   @param recordType Record type from RecordType enum data type
   @return { "record": "JSON-encoded record data" }
   */
  function getRecord (string domain, RecordType recordType)
                      domainShouldExist(domain)
                      constant returns (string record) {
    return domainToRecords[domain][uint(recordType)];
  }

  /**
   @notice Delete DNS record of a registered domain
   @param domain Domain name
   @param recordType Record type from RecordType enum data type
   */
  function deleteRecord (string domain, RecordType recordType)
                         domainShouldExist(domain)
                         onlyByOwner(domain) {
    delete domainToRecords[domain][uint(recordType)];
  }

  /**
   @notice Delete a registered domain
   @param domain Domain name
   */
  function deleteDomain (string domain)
                        domainShouldExist(domain)
                        onlyByOwner(domain) {
  	address owner = msg.sender;

    removeDomainOwner(domain, owner);
    removeAllRecordsOfDomain(domain);

    delete domainToCreated[domain];
    delete domainToUpdated[domain];
  }

  /**
   @notice Get registered domain count of an ether address
   @param owner Ether address (pass null string to set caller as owner)
   @return { "count": "Number of domain registered" }
   */
  function getDomainCount (address owner) constant returns (uint count) {
    if (owner == address(0x0)) owner = msg.sender;

    return ownerToDomains[owner].length;
  }

  /**
   @notice Get domain name from index
   @param index Index of domain
   @param owner Ether address (pass null string to set caller as owner)
   @return { "domain": "Domain name" }
   */
  function getDomainFromIndex (uint index, address owner) constant
                               returns (string domain) {
    if (owner == address(0x0)) owner = msg.sender;

    if (index >= ownerToDomains[owner].length) return;

    return ownerToDomains[owner][index];
  }

  function setDomainOwner (string domain, address owner) private {
    domainToOwner[domain] = owner;
    domainToOwnerArrayIndex[domain] = ownerToDomains[owner].length;
    ownerToDomains[owner].push(domain);
  }

  function removeDomainOwner (string domain, address owner) private {
    uint indexOfDomain = domainToOwnerArrayIndex[domain];
    string[] domainArray = ownerToDomains[owner];
    uint indexOfLastDomain = domainArray.length - 1;

    if (indexOfDomain != indexOfLastDomain) {
      string lastDomain = domainArray[indexOfLastDomain];
      domainArray[indexOfDomain] = lastDomain;
      domainToOwnerArrayIndex[lastDomain] = indexOfDomain;
    }

    delete domainArray[indexOfLastDomain];
    domainArray.length--;

    delete domainToOwner[domain];
    delete domainToOwnerArrayIndex[domain];
  }

  function removeAllRecordsOfDomain (string domain) private {
    for (uint i = 0; i < totalRecordTypes; i++) {
      delete domainToRecords[domain][i];
    }
  }
}
