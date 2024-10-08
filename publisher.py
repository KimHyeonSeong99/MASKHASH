import hashlib
import os
import sys
import base64
import json
import paho.mqtt.client as mqtt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

program_path = os.getcwd()
path = {"firmware": os.path.join(program_path,"update_firmware"),"image": os.path.join(program_path,"update_image")}
update_path = os.path.join(program_path,"updated")
Sub_Topic = "updates"
userId = "Alice"
userPw = "mose"
brokerIp = "203.246.114.226"
port = 1883
ecu_information = 'E120RS19A8000'


def get_master_key():
    master_key_path = os.path.join(os.getcwd(),'MASTERKEY.txt')
    try:
        with open(os.path.join(os.getcwd(),'MASTERKEYHASH.txt')) as hash:
            master_key_hash = hash.read()
        if compute_file_hash(master_key_path) == master_key_hash:
                    with open(master_key_path,'r') as file:
                        master_key = file.read()
        else:
            print("The master key has some problem! Stop processing now!")
            sys.exit()

    except FileNotFoundError as e:
        print(e)
        sys.exit()

    return master_key
        
# Function to compute the SHA-256 hash of a file
def compute_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def compute_file_hash_with_mask(file_path, mask):
    sha256_hash = hashlib.sha256()
    mask = mask.encode('utf-8')
    
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(512), b""):
            masked_chunk = bytes(a ^ b for a, b in zip(chunk, mask))
            sha256_hash.update(masked_chunk)
    
    return sha256_hash.hexdigest()

def generate_mask(password: str, chassis_number: bytes = None, ECU_information: bytes= None, iterations: int = 100000) -> bytes:
    salt = chassis_number + ECU_information
    derived_key = hashlib.pbkdf2_hmac(
        'sha512',
        password.encode('utf-8'),
        salt,
        iterations,  
        dklen=512  
    )
    return derived_key.hex()

# MQTT event handlers
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected OK")
        client.subscribe("request")  # Subscribe to the request topic for file transfer
    else:
        print("Error: Connection failed, Return code =", rc)

def on_disconnect(client, userdata, rc=0):
    print("Disconnected with return code:", rc)
    
def on_publish(client, userdata, mid):
    print("In on_publish callback mid =", mid)

# Function to create the message with file details and content
def make_message(file_path):
    file_name = os.path.basename(file_path)
    split_file_name = file_name.split('-')
    message = dict()
    message['flag'] = 'update'
    message['file_name'] = split_file_name[-1]
    message['version'] = split_file_name[1]
    message['target'] = split_file_name[0]
    if file_name.endswith('.png'):
        message['type'] = 'image'
    else:
        message['type'] = 'firmware'
    try:
        with open(file_path, 'rb') as file:
            message['file'] = base64.b64encode(file.read()).decode('utf-8')

        print('='*30)
        print("File name: " + message['file_name'])
        print("File version: " + message['version'])
        print("File target: " + message['target'])
        print('='*30)
        return message

    except FileNotFoundError as e:
        print("Error:", e)
        return None
    
# MQTT event handler for incoming file requests
def on_message(client, userdata, msg):
    request = json.loads(msg.payload)
    # Assuming the payload is the file path
    if request['flag'] == 'request':
        print(f"Received request: {request}")
        try:
            file_path = os.path.join(update_path,request['file_name'])
            vehicle_features = request['vehicle_features']
            message = make_message(file_path)
            message['flag'] = 'update'
            message['hash'] = compute_file_hash(file_path)  # Add file hash to the message
            message['mask_hash'] = compute_file_hash_with_mask(file_path, generate_mask(master_key, vehicle_features.encode('utf-8'), ecu_information.encode('utf-8')))
            print(f"File hash: {message['hash']}")
            print(f"File mask hash: {message['mask_hash']}")
            
            # Publish the message to the MQTT topic
            client.publish(f"update/{message['file_name']}", json.dumps(message), 0, retain = True)
            print("File sent successfully.")
        
        except ValueError as e: 
            print(f"Received fault[{e}] request")
    else:
        print("Failed to create the message.")


# Function to notify the vehicle of a new file
def notify_new_file(client, file_path):
    file_name = os.path.basename(file_path)

    try:
        with open(file_path, "rb") as stream:
            data = stream.read()

    except FileNotFoundError as e:
        print("Error:", e)
        return None

    notification = dict()
    notification['flag']= 'notification'
    notification['file_name'] = file_name
    save_path = os.path.join(update_path,notification['file_name'])
    with open(save_path, "wb") as stream:
        stream.write(data)
    
    # Publish the notification
    client.publish("notify", json.dumps(notification), 2, retain = True)
    print("Notification sent for new file:", notification)

# Event handler for directory monitoring
class NewFileHandler(FileSystemEventHandler):
    def __init__(self, client):
        self.client = client

    def on_created(self, event):
        if not event.is_directory:  # Ensure it's a file, not a directory
            print(f"New file detected: {event.src_path}")
            notify_new_file(self.client, event.src_path)

# Main function to set up the MQTT client and directory monitoring
def main():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    client.on_message = on_message

    # Connect to the broker
    client.connect(brokerIp, 1883, 60)

    # Set up directory monitoring
    event_handler = NewFileHandler(client)
    observer_firmware = Observer()
    observer_firmware.schedule(event_handler, path['firmware'], recursive=False)
    observer_firmware.start()
    event_handler = NewFileHandler(client)
    observer_image = Observer()
    observer_image.schedule(event_handler, path['image'], recursive=False)
    observer_image.start()

    try:
        # Start the MQTT loop to process network traffic and callbacks
        client.loop_start()
        os.system("cls")
        print("Monitoring directory")
        while True:
            pass  # Keep the script running to monitor the directory
    except KeyboardInterrupt:
        observer_firmware.stop()
        observer_image.stop()

    observer_firmware.join()
    observer_image.join()

if __name__ == "__main__":
    master_key = get_master_key()
    main()
