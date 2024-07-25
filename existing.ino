#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

const char* ssid = "Redmi";
const char* password = "AT18FORLIFE";
const char* mqtt_server = "192.168.88.192";  // Replace with your Raspberry Pi IP address
const char* passkey = "CIOT_123"; // Define your passkey here

WiFiClient espClient;
PubSubClient client(espClient);

String generateDeviceID() {
  String mac = WiFi.macAddress();
  mac.replace(":", ""); // Remove colons from MAC address
  String randomPart = String(random(0x0000, 0xFFFF)); // Generate a random part
  return "ESP8266_" + mac + "_" + randomPart; // Combine MAC and random part
}

String device_id;

void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(0));  // Seed the random generator
  setup_wifi();
  device_id = generateDeviceID(); // Generate random device ID based on MAC and random part
  client.setServer(mqtt_server, 1883);
  reconnect();
  publishMetadata();
}

void setup_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    if (client.connect("ESP8266Client")) {
      Serial.println("connected");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      delay(5000);
    }
  }
}

void publishMetadata() {
  // Create JSON payload
  StaticJsonDocument<200> doc;
  doc["device_id"] = device_id;
  doc["mac_address"] = WiFi.macAddress();
  doc["firmware_version"] = ESP.getSdkVersion();
  doc["passkey"] = passkey; // Add passkey to the JSON payload

  char buffer[256];
  serializeJson(doc, buffer);

  Serial.print("Publishing message: ");
  Serial.println(buffer);

  // Publish metadata
  if (client.publish("esp8266/metadata", buffer)) {
    Serial.println("Publish succeeded");
  } else {
    Serial.println("Publish failed");
  }
}

void loop() {
  // No need to do anything in loop
}
