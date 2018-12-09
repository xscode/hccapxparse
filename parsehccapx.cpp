#include <iostream>
#include <fstream>
#include <string.h>
#include <sstream>
#include  <iomanip>

using namespace std;

struct hccapx // As laid oput on https://hashcat.net/wiki/doku.php?id=hccapx
{
  uint32_t signature;
  uint32_t version;
  uint8_t message_pair;
  uint8_t essid_len;
  uint8_t essid[32];
  uint8_t keyver;
  uint8_t  keymic[16];
  uint8_t  mac_ap[6];
  uint8_t  nonce_ap[32];
  uint8_t  mac_sta[6];
  uint8_t  nonce_sta[32];
  uint16_t eapol_len;
  uint8_t  eapol[256];
} __attribute__((packed));

string charArrayToString(uint8_t carray[],int arraylen, bool mac){
// "nicify's the hex parts output and adds ":" deliminators for MAC addresses
stringstream tmp_return;
    for (int i=0;i<arraylen;i++){
        tmp_return << uppercase << setfill('0') << setw(2) << hex << int(carray[i]);
        if (mac && i < 5 ){tmp_return << ":";}
    }
    return tmp_return.str();
}

string printnicehex(string data, int data_len, int columnWidth){
    stringstream tmpreturn;
    int i = -1;
    while (data_len - (i*columnWidth) >= columnWidth){
        i++;
        if (i > 0){tmpreturn << "               ";}
        tmpreturn << data.substr(i*columnWidth,columnWidth) << "\n";
        }
    if (i*columnWidth != data_len) {tmpreturn << "               " << data.substr(i*columnWidth,int(data_len)-(i*columnWidth)) << "\n";}
    return tmpreturn.str();
}

int main(int argc, char *argv[]){
    // check for args and print usage if none
    if (argc > 0) {
      hccapx packet;
      ifstream capfile;
      // open specified file
      capfile.open (argv[1], std::ifstream::binary);
      if (capfile.is_open())
      {
        int i = 0;
        // File should be multiples of 393 bytes so read chunks of 393 until EOF
        while (!capfile.eof())
        {
          char buffer[393];
          capfile.read (buffer, 393);
          //map the buffer to the HCCAPX typeed variable
          memcpy(&packet,&buffer,393);
          //check for valid HCCAPX packet/file
          if (packet.signature != 0x58504348){
            cout << "Not a valid HCCAPX file";
            capfile.close();
            exit(0);
          }
          //Print out the parsed data
          cout << "Packet " << i+1 << ":\n";
          cout << "------------------------------------------------\n";
          //cout << "Signature    : " << packet.signature << "\n";
          cout << "Version      : " << int(packet.version) << "\n";
          cout << "Message Pair : " << int(packet.message_pair) << "\n";
          cout << "ESSID Len    : " << int(packet.essid_len) << "\n";
          cout << "ESSID        : " << packet.essid << "\n";
          cout << "Key Ver      : " << int(packet.keyver) << "\n";
          cout << "Key Mic      : " << charArrayToString(packet.keymic,sizeof(packet.keymic) / sizeof(packet.keymic[0]),false) << "\n";
          cout << "AP MAC       : " << charArrayToString(packet.mac_ap,sizeof(packet.mac_ap) / sizeof(packet.mac_ap[0]),true) << "\n";
          cout << "AP Nonce     : " << printnicehex(charArrayToString(packet.nonce_ap,sizeof(packet.nonce_ap) / sizeof(packet.nonce_ap[0]),false),32,16);
          cout << "Sta MAC      : " << charArrayToString(packet.mac_sta,sizeof(packet.mac_sta) / sizeof(packet.mac_sta[0]),true) << "\n";
          cout << "Sta Nonce    : " << printnicehex(charArrayToString(packet.nonce_sta,sizeof(packet.nonce_sta) / sizeof(packet.nonce_sta[0]),false),32,16);
          cout << "EAPOL Len    : " << int(packet.eapol_len) << "\n";
          cout << "EAPOL        : ";
          cout << printnicehex(charArrayToString(packet.eapol,int(packet.eapol_len),false),int(packet.eapol_len),16);
          cout << "------------------------------------------------\n";
          i++;
        }
        capfile.close();
      } else
      {
        cout << "Could not open file " << argv[1];
      }
    } else {
      cout << "Usage: parsehccapx <capfile.hccapx>\n";
    }

    return 0;
}
