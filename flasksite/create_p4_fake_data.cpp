#include <iostream>
#include <fstream>
#include <cstdint>

#pragma pack(push, 1)
struct switch_t {
    uint8_t kind;
    uint8_t length;
    uint32_t as_number; // AS number; 65'536 - 65'551
    uint8_t as_country; // location of AS

    uint8_t as_type:3; // type of AS (e.g. IXP, CDN)
    uint8_t as_rov_score:1; // ROV Score of AS (1 for 100% or 0 for less)
    uint8_t as_manrs_member:1; // indicates if AS is participating in MANRS (best routing practices); 1 - member, 0 - non-member
    uint8_t as_mb_risk:2; // middlebox risk level 0-3 scale;
    //uint8_t padding:1;
    uint8_t as_ldap_risk:1; // LDAP risk level: 0 - no risk, 1 - risk
};
#pragma pack(pop)

int main(int argc, char** argv) {
    std::cout << "This is a test for creating P4 fake data." << std::endl;
    std::cout << sizeof(switch_t) << " bytes" << std::endl;
    switch_t h;

    // scenario 1: up path has high MB risk and no LDAP risk but participate in MANRS and has ROV score
    // scenario 2: low path has low MB risk and has LDAP risk but does not participate in MANRS and has no ROV score

    // paths
    //       --- AS2 --- AS3 ---
    //     /                     \
    // AS1 ---- AS6 --- AS7 ------ AS4

    // AS 1 (ASN 65537); entry AS; EU; support ROV, MANRS, low MB risk, no LDAP risk
    h.kind = 0x72;
    h.length = 8;
    h.as_number = 65'537;
    h.as_country = 4;
    h.as_type = 1;
    h.as_rov_score = 1;
    h.as_manrs_member = 1;
    h.as_mb_risk = 0;
    h.as_ldap_risk = 0;
    std::ofstream outfile("../research_data/p4_fake_data_as1.bin", std::ios::binary);
    outfile.write(reinterpret_cast<char*>(&h), sizeof(h));
    outfile.close();

    // AS 4 (ASN 65538); exit AS; EU; support ROV, MANRS, low MB risk, no LDAP risk
    h.kind = 0x72;
    h.length = 8;
    h.as_number = 65'538;
    h.as_country = 6;
    h.as_type = 2;
    h.as_rov_score = 1;
    h.as_manrs_member = 1;
    h.as_mb_risk = 0;
    h.as_ldap_risk = 0;
    outfile = std::ofstream("../research_data/p4_fake_data_as4.bin", std::ios::binary);
    outfile.write(reinterpret_cast<char*>(&h), sizeof(h));
    outfile.close();

    // Upper path (EU)
    // AS 2 (ASN 65539); has MANRS and ROV, mild MB risk, no LDAP risk
    h.kind = 0x72;
    h.length = 8;
    h.as_number = 65'539;
    h.as_country = 5;
    h.as_type = 1;
    h.as_rov_score = 1;
    h.as_manrs_member = 1;
    h.as_mb_risk = 1;
    h.as_ldap_risk = 0;
    outfile = std::ofstream("../research_data/p4_fake_data_as2.bin", std::ios::binary);
    outfile.write(reinterpret_cast<char*>(&h), sizeof(h));
    outfile.close();

    // AS 3 (ASN 65540); has MANRS and ROV, moderate MB risk, no LDAP risk
    h.kind = 0x72;
    h.length = 8;
    h.as_number = 65'540;
    h.as_country = 19;
    h.as_type = 1;
    h.as_rov_score = 0;
    h.as_manrs_member = 0;
    h.as_mb_risk = 2;
    h.as_ldap_risk = 0;
    outfile = std::ofstream("../research_data/p4_fake_data_as3.bin", std::ios::binary);
    outfile.write(reinterpret_cast<char*>(&h), sizeof(h));
    outfile.close();

    // Lower path (NON-EU)
    // AS 6 (ASN 65541); no MANRS, no ROV, low MB risk, with LDAP risk
    h.kind = 0x72;
    h.length = 8;
    h.as_number = 65'541;
    h.as_country = 10;
    h.as_type = 1;
    h.as_rov_score = 1;
    h.as_manrs_member = 1;
    h.as_mb_risk = 0;
    h.as_ldap_risk = 0;
    outfile = std::ofstream("../research_data/p4_fake_data_as6.bin", std::ios::binary);
    outfile.write(reinterpret_cast<char*>(&h), sizeof(h));
    outfile.close();

    // AS 7 (ASN 65542); no MANRS, has ROV, low MB risk, with LDAP risk
    h.kind = 0x72;
    h.length = 8;
    h.as_number = 65'542;
    h.as_country = 18;
    h.as_type = 1;
    h.as_rov_score = 1;
    h.as_manrs_member = 1;
    h.as_mb_risk = 0;
    h.as_ldap_risk = 0;
    outfile = std::ofstream("../research_data/p4_fake_data_as7.bin", std::ios::binary);
    outfile.write(reinterpret_cast<char*>(&h), sizeof(h));
    outfile.close();

    return 0;
}
