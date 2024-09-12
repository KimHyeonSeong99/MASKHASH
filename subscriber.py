import paho.mqtt.client as mqtt
import json, io
import os, cv2, base64
import time
from tkinter import *
from tkinter import messagebox
import socket
import numpy as np
import hashlib

timelist = {'Now':0,'10min':600,'1hour':3600,'1day':86400,'1week':604800}
Sub_Topic = "update/" 
userId = "Alice"
userPw = "mose"
brokerIp = "203.246.114.226"
port = 1883
server_host = {'cluster':"203.246.114.226"}
server_port = 12345
tmp_directory = "C:/Users/user/MASKHASH/tmp/"
chassis_number = '1A31874UEQ'

def compute_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    with open(tmp_directory + 'version.json', 'r') as version_json:
        version = json.load(version_json)
    for key in version.keys():
        client.subscribe(Sub_Topic+ key)
    client.subscribe("notify")

def update_choice():
    OTA_UI = Tk()
    later_time = StringVar()
    OTA_UI.title("Choice update")
    window_width = OTA_UI.winfo_screenwidth()
    window_height = OTA_UI.winfo_screenheight()
    app_width = 500
    app_height = 300
    width_center = int((window_width - app_width)/2)
    height_center = int((window_height - app_height)/2)
    OTA_UI.geometry(f"{app_width}x{app_height}+{width_center}+{height_center}")
    information = Label(OTA_UI,text = 'Do you want to update new firmware?\nclick the button what you want',font = ('bold'))
    
    def event_PB():
        if later_time.get() == 'Now':
            messagebox.showinfo("Notice","You choice Now, Start install firmware!")
            OTA_UI.destroy()

        elif later_time.get() == '':
            messagebox.showinfo("Notice","You choice Now, Start install firmware!")
        else:
            messagebox.showinfo("Notice",f"You choice Later, Notice update after {later_time.get()} later!")
            OTA_UI.destroy()
            
    button_Submit = Button(OTA_UI,text = 'Submit',command = event_PB)
    Later_time0 = Radiobutton(OTA_UI, text = 'Now', value = 'Now', variable = later_time)
    Later_time1 = Radiobutton(OTA_UI, text = '10 min', value = '10min', variable = later_time)
    Later_time2 = Radiobutton(OTA_UI, text = '1 hour', value = '1hour', variable = later_time)
    Later_time3 = Radiobutton(OTA_UI, text = '1 day', value = '1day', variable = later_time)
    Later_time4 = Radiobutton(OTA_UI, text = '1 week', value = '1week', variable = later_time)
    information.pack()
    button_Submit.pack()
    Later_time0.pack()
    Later_time1.pack()
    Later_time2.pack()
    Later_time3.pack()
    Later_time4.pack()
    OTA_UI.mainloop()
    return timelist.get(later_time.get())

def ignore_error_alert():
    choice = {'Retry': 1, 'Stop': 0}
    OTA_UI = Tk()
    choice_retry = StringVar()
    OTA_UI.title("ignore error alert")
    window_width = OTA_UI.winfo_screenwidth()
    window_height = OTA_UI.winfo_screenheight()
    app_width = 500
    app_height = 300
    width_center = int((window_width - app_width)/2)
    height_center = int((window_height - app_height)/2)
    OTA_UI.geometry(f"{app_width}x{app_height}+{width_center}+{height_center}")
    information = Label(OTA_UI,text = 'Detect firmware ignore error!\nclick the button what you want',font = ('bold'))
    
    def event_PB():
        if choice_retry.get() == 'Retry':
            messagebox.showinfo("Notice","You choice \'Retry\', Retry install firmware!")
            OTA_UI.destroy()
            return 1
        elif choice_retry.get() == 'Stop':
            messagebox.showinfo("Notice","You choice \'Stop\', Stop install firmware!")
            OTA_UI.destroy()
            return 0
        else:
            messagebox.showinfo("Notice","You must choice \'Retry\' or \'Stop\'!")
            
    button_Submit = Button(OTA_UI,text = 'submit',command = event_PB)
    choice_retry_retry_0 = Radiobutton(OTA_UI, text = 'Retry', value = 'Retry', variable = choice_retry)
    choice_retry_retry_1 = Radiobutton(OTA_UI, text = 'Stop', value = 'Stop', variable = choice_retry)
    information.pack()
    button_Submit.pack()
    choice_retry_retry_0.pack()
    choice_retry_retry_1.pack()
    OTA_UI.mainloop()
    return choice.get(choice_retry.get())

def send_file(server_host, server_port, message, buffer_size=4096):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_host, server_port))
        print(f"Connected to server {server_host}:{server_port}")
        client_socket.sendall(message.encode('utf-8'))
        print("File sent successfully.")

# subscriber callback
def on_message(client, userdata, msg):

    try:
        version_path = os.path.join(tmp_directory,"version.json")
        with open(version_path,"r") as versionlist:
            version = json.load(versionlist)
    except:
        version = dict()

    payload = json.loads(msg.payload)
    flag = payload['flag']
    if flag == 'notification':
        file_name = payload['file_name'].split('-')[-1]
        file_version = payload['file_name'].split('-')[1]
        if float(version[file_name]) < float(file_version):
            print("Receive a update notify")
            choice = 1
            while(choice):
                choice = update_choice()
                time.sleep(choice)
            payload['flag'] = 'request'
            payload['vehicle_features'] = chassis_number
            client.publish("request",json.dumps(payload))
            print("Request sent for new file:", payload)

        else:
            print("="*50)
            print("File name: " + file_name)
            print("File version: " + file_version)
            print("Latest version: " + version[file_name])
            print("new firmware version is old version, pass the update")
            print("="*50)

    elif flag == 'update':
        file_name = payload['file_name']
        file_version = payload['version']
        file_type = payload['type']
        file_hash = payload['hash']
        file_mask_hash = payload['mask_hash']
        file_target = payload['target']
        if file_type == 'firmware':
            try:
                file_data = payload['file']
            except:
                print('Error: wrong type!')
            try:
                file_path = os.path.join(tmp_directory, file_name)
                with open(file_path,"w", encoding='utf-8') as stream:
                    stream.write(file_data)
                time.sleep(1)
                print(f"File downloaded and saved to {tmp_directory}")
            except Exception as e:
                print(f"Error downloading the file: {e}")
                print(f"file directory: {tmp_directory}")
                print(f"file path: {file_path}")
        else:
            ImageData = payload['file'].encode()
            decode_img = base64.b64decode(ImageData)
            img_out = Image.open(io.BytesIO(decode_img))
            img_array = np.array(img_out)
            img = cv2.cvtColor(img_array, cv2.COLOR_BGR2RGB)
            cv2.imwrite(file_path, img)
        computed_file_hash = compute_file_hash(file_path)
        print(f'{file_hash}:{computed_file_hash}')
        if file_hash == computed_file_hash:
            with open(file_path, 'rb') as file:
                file_contents = file.read()
            try:
                if file_type == 'image':
                    message = f'\\image\\{file_name}:{file_mask_hash}:{file_contents}'
                else:
                    message = f'{file_name}:{file_mask_hash}:{file_contents}'
                try_update = 1
            except:
                print("Fail Make message")
                try_update = 0

            while(try_update):  
                try:
                    send_file(server_host.get(file_target), server_port, message)
                    try_update = 0
                    version[file_name] = file_version
                    with open(version_path,"w") as versionlist:
                        versionlist.write(json.dumps(version))
                except:
                    print("Cluster and Controller are not conected! \nRetry send file")
                    time.sleep(10)

        else:
            if ignore_error_alert():
                request = {}
                request['flag'] = 'request'
                request['vehicle_features'] = chassis_number
                request['file_name'] = '-'.join([payload['target'],payload['version'],payload['file_name']])
                print("Request sent for file:", request)
                client.publish("request",json.dumps(payload))

        print("Ready for a new update")

    else:
        print('Receive wrong form message!')

os.system("cls")
client = mqtt.Client()
client.username_pw_set(userId, userPw)
client.on_connect = on_connect
client.on_message = on_message

client.connect(brokerIp, port, 60)

client.loop_forever()