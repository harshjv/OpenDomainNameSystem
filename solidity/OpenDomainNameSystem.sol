import 'library/strings.sol';

pragma solidity ^0.4.2;

contract OpenDomainNameSystem {
  using strings for *;

  struct WHOIS {
    address ethAddr;
    string name;

    string addr;
    string phone;
    string email;

    uint created;
    uint updated;
  }

  enum RecordType { A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, NAPTR, OPT, SPF, TLSA }
  uint constant totalRecordTypes = uint(RecordType.TLSA);

  // domain => owner
  mapping(string => address) domainToAddress;
  // address => domains
  mapping(address => string[]) addressToDomains;
  // domain => records
  mapping(string => mapping(uint => string)) domainToRecords;
  // domain => WHOIS
  mapping(string => WHOIS) domainToWhois;

  modifier domainShouldNotExist (string domain) {
    if (domainToAddress[domain] != address(0x0)) throw;
    _;
  }

  modifier domainShouldExist (string domain) {
    if (domainToAddress[domain] == address(0x0)) throw;
    _;
  }

  modifier onlyByOwner(string domain) {
    address sender = msg.sender;
    address owner = domainToAddress[domain];

    if (owner != sender) throw;
    _;
  }

  function OpenDomainNameSystem () {}

  function registerDomain (string domain, string name, string addr,
                           string phone, string email)
                           domainShouldNotExist(domain) {
  	address owner = msg.sender;
    domainToAddress[domain] = owner;
    addressToDomains[owner].push(domain);
    domainToWhois[domain] = WHOIS(owner, name, addr, phone, email, now, now);
  }

  function transferDomain (string domain, address newOwner, string name,
                           string addr, string phone, string email)
                           domainShouldExist(domain)
                           onlyByOwner(domain) {
    uint limit = addressToDomains[msg.sender].length - 1;
    bool found = false;

    for (uint i = 0; i <= limit; i++) {
      if (!found &&
          addressToDomains[msg.sender][i].toSlice().equals(domain.toSlice())) {
        found = true;
      }

      if (found && i != limit) {
        addressToDomains[msg.sender][i] = addressToDomains[msg.sender][i + 1];
      }
    }

    delete addressToDomains[msg.sender][limit];
    addressToDomains[msg.sender].length--;

    addressToDomains[newOwner].push(domain);
    domainToAddress[domain] = newOwner;

    domainToWhois[domain] = WHOIS(newOwner, name, addr, phone, email,
                                  domainToWhois[domain].created, now);
  }

  function setWhoisData (string domain, string name, string addr,
                         string phone, string email)
                         domainShouldExist(domain)
                         onlyByOwner(domain) {
    address owner = msg.sender;
    WHOIS oldWhoisData = domainToWhois[domain];

    name = bytes(name).length == 0 ? oldWhoisData.name : name;
    addr = bytes(addr).length == 0 ? oldWhoisData.addr : addr;
    phone = bytes(phone).length == 0 ? oldWhoisData.phone : phone;
    email = bytes(email).length == 0 ? oldWhoisData.email : email;

    domainToWhois[domain] = WHOIS(owner, name, addr, phone, email, oldWhoisData.created, now);
  }

  function getWhoisData (string domain)
                        domainShouldExist(domain)
                        constant public returns (address ethAddr, string name,
                                        string addr, string phone,
                                        string email, uint256 created,
                                        uint256 updated) {
    WHOIS whois = domainToWhois[domain];

    ethAddr = whois.ethAddr;
    name = whois.name;
    addr = whois.addr;
    phone = whois.phone;
    email = whois.email;
    created = whois.created;
    updated = whois.updated;
  }

  function setRecord (string domain, RecordType recordType, string data)
                         domainShouldExist(domain)
                         onlyByOwner(domain) {
    domainToRecords[domain][uint(recordType)] = data;
  }

  function getRecord (string domain, RecordType recordType)
                      domainShouldExist(domain)
                      onlyByOwner(domain)
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
                        onlyByOwner(domain) public {
  	address owner = msg.sender;
    uint limit = addressToDomains[owner].length - 1;
    bool found = false;

    for (uint i = 0; i <= limit; i++) {
      if (!found &&
          addressToDomains[owner][i].toSlice().equals(domain.toSlice())) {
        found = true;
      }

      if (found && i != limit) {
        addressToDomains[owner][i] = addressToDomains[owner][i + 1];
      }
    }

    delete addressToDomains[owner][limit];
    addressToDomains[owner].length--;
    delete domainToAddress[domain];

    for (uint j = 0; j < totalRecordTypes; j++) {
      delete domainToRecords[domain][j];
    }
  }

  function getDomainCount (address owner) constant public returns (uint) {
    if (owner == address(0x0)) owner = msg.sender;

    return addressToDomains[owner].length;
  }

  function getDomain (uint index, address owner) constant public returns (string) {
    if (owner == address(0x0)) owner = msg.sender;

    if (index >= addressToDomains[owner].length) return;

    return addressToDomains[owner][index];
  }
}
