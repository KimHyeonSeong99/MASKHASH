import os
import socket
import hashlib

file_dir = os.path.join(os.getcwd(),"download")
mask = 'dec3e8d98485ee7b79955d0ebad0f8cf2025109fa26ef04ea690057f105b13c7bb2982476fb5ebb2dd4f5358d9574ad1c1529c8f21e4ec72552876a67ca3ef41bc7686ded0dc293c3f146c1ff925c405e41c8c1e01b1f03588138a6471264e604b27f034880d802ccab05bd42a852c8bc12fbe22fd5e939f61b5af348d90b30c6cb409951a178d4d7cb4a3771a796fe894559b22c83c38dce9074946a03702cba268846b51a6b2b4a62ad335cfb13e72fcafd33deb4463240bca991fb038ff33536a3a0497ebdb63b2a4e6a0cf1d97df52cc2e1d5552297e7e2fb9d6add994ca15725f4f1c82e7e74db954542e13bfc3c08331fd7de53cf4c777d446a7ae5240a224cce8f9bef3383705a7b7bd211de20a3d153cfd32408577f323733711509b45b8ede70f3202bf5a171df6e77cf6673753e58f2833bc33dd320cb973e76447b1ceb51bc64499f66282148f3804049027cf2dbdb66882d00a06903e25f64358398548450b57789b6f818481464e2a98efc5a049cdff4978ccec79a0efd6313c9d5aa4e001124226518a748540b591e865821024573527c1393fce1e7a79e0d73586738ba06d17d3b6f01841755b2aab0c6edbf907aac2f74016c8c587f4a71d1dea60691dfb10cc8d99ee5771e2325f0b7ae436cc89bc59eabb30616b2cfa123b4829e5d9440e61753cd1ebf1f9e2c09f172f04552ac976688c65dc8979a3d6'

def compute_file_hash_with_mask(file_path, mask):
    sha256_hash = hashlib.sha256()  
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(512), b""):
            masked_chunk = bytes(a ^ b for a, b in zip(chunk, mask))
            sha256_hash.update(masked_chunk)
    
    return sha256_hash.hexdigest()


def receive_file(server_host, server_port, buffer_size=4096):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((server_host, server_port))
        server_socket.listen(1)
        print(f"Server listening on {server_host}:{server_port}")
        
        conn, addr = server_socket.accept()
        with conn:
            message = b""
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(buffer_size)
                if not data:
                    break
                message += data

            split_message = message.split(b":",2)
            file_name = split_message[0].decode('utf-8')
            file_mask_hash = split_message[1].decode('utf-8')
            file_content = split_message[2].decode('utf-8')
            
            file_path = os.path.join(file_dir, file_name)
            with open(file_path, "w", encoding='utf-8') as f:
                f.write(file_content)
                if file_mask_hash == compute_file_hash_with_mask(file_path, mask):
                    os.chdir('/home/sea/sea-me-hackathon-2023/Cluster/src/')
                    os.system("make -j6")
                else:
                    print("Detect file ignore error!")

            print("File received successfully.")
                
server_host = "0.0.0.0"  # Listen on all interfaces
server_port = 12345

os.system("cls")
while True:
    receive_file(server_host, server_port)
    
