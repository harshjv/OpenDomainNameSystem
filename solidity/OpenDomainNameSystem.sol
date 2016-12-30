pragma solidity ^0.4.2;

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

  function registerDomain (string domain, string whois)
                           domainShouldNotExist(domain)
                           domainCreated(domain)
                           domainUpdated(domain) {
  	address owner = msg.sender;

    setDomainOwner(domain, owner);

    domainToWhois[domain] = whois;
  }

  function transferDomain (string domain, address newOwner, string whois)
                           domainShouldExist(domain)
                           onlyByOwner(domain)
                           domainUpdated(domain) {
    address oldOwner = msg.sender;

    removeDomainOwner(domain, oldOwner);
    removeAllRecordsOfDomain(domain);
    setDomainOwner(domain, newOwner);

    domainToWhois[domain] = whois;
  }

  function setWhoisData (string domain, string whois)
                         domainShouldExist(domain)
                         onlyByOwner(domain)
                         domainUpdated(domain) {
    domainToWhois[domain] = whois;
  }

  function getWhoisData (string domain)
                        domainShouldExist(domain)
                        constant returns (address, string, uint, uint) {
    address owner = domainToOwner[domain];
    string whois = domainToWhois[domain];
    uint created = domainToCreated[domain];
    uint updated = domainToUpdated[domain];

    return (owner, whois, created, updated);
  }

  function setRecord (string domain, RecordType recordType, string data)
                         domainShouldExist(domain)
                         onlyByOwner(domain) {
    domainToRecords[domain][uint(recordType)] = data;
  }

  function getRecord (string domain, RecordType recordType)
                      domainShouldExist(domain)
                      constant returns (string) {
    return domainToRecords[domain][uint(recordType)];
  }

  function deleteRecord (string domain, RecordType recordType)
                         domainShouldExist(domain)
                         onlyByOwner(domain) {
    delete domainToRecords[domain][uint(recordType)];
  }

  function deleteDomain (string domain)
                        domainShouldExist(domain)
                        onlyByOwner(domain) {
  	address owner = msg.sender;

    removeDomainOwner(domain, owner);
    removeAllRecordsOfDomain(domain);

    delete domainToCreated[domain];
    delete domainToUpdated[domain];
  }

  function getDomainCount (address owner) constant returns (uint) {
    if (owner == address(0x0)) owner = msg.sender;

    return ownerToDomains[owner].length;
  }

  function getDomainFromIndex (uint index, address owner) constant returns (string) {
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
