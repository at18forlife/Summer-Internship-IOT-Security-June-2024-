import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import firebase_admin
from firebase_admin import credentials, db
import rsa
from Crypto.Hash import keccak
import paho.mqtt.client as mqtt
from web3 import Web3

class BlockchainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Application")

        # Initialize Firebase
        cred = credentials.Certificate('credentials.json')
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://metadata-2bce6-default-rtdb.asia-southeast1.firebasedatabase.app'
        })
        self.ref = db.reference('metadata')

        # Initialize MQTT
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.connect("localhost", 1883, 60)
        self.mqtt_client.loop_start()

        # Connect to Ganache
        self.w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        self.account = self.w3.eth.accounts[0]

        # Replace with actual ABI and Bytecode
        self.abi = [
            {
      "constant": True,
      "inputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "metadata",
      "outputs": [
        {
          "internalType": "string",
          "name": "deviceId",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "macAddress",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "firmwareVersion",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "publicKey",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "privateKey",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "contractAddress",
          "type": "string"
        }
      ],
      "payable": False,
      "stateMutability": "view",
      "type": "function"
    },
    {
      "constant": True,
      "inputs": [],
      "name": "metadataCount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "payable": False,
      "stateMutability": "view",
      "type": "function"
    },
    {
      "constant": False,
      "inputs": [
        {
          "internalType": "string",
          "name": "deviceId",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "macAddress",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "firmwareVersion",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "publicKey",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "privateKey",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "contractAddress",
          "type": "string"
        }
      ],
      "name": "addMetadata",
      "outputs": [],
      "payable": False,
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "constant": True,
      "inputs": [
        {
          "internalType": "uint256",
          "name": "index",
          "type": "uint256"
        }
      ],
      "name": "getMetadata",
      "outputs": [
        {
          "internalType": "string",
          "name": "deviceId",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "macAddress",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "firmwareVersion",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "publicKey",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "privateKey",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "contractAddress",
          "type": "string"
        }
      ],
      "payable": False,
      "stateMutability": "view",
      "type": "function"
    }
        ]
        self.bytecode = '0x608060405234801561001057600080fd5b506113d3806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c8063342afb7e14610051578063367456951461006f578063a574cea41461041d578063e3684e39146106e0575b600080fd5b6100596109a3565b6040518082815260200191505060405180910390f35b61041b600480360360c081101561008557600080fd5b81019080803590602001906401000000008111156100a257600080fd5b8201836020820111156100b457600080fd5b803590602001918460018302840111640100000000831117156100d657600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192908035906020019064010000000081111561013957600080fd5b82018360208201111561014b57600080fd5b8035906020019184600183028401116401000000008311171561016d57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290803590602001906401000000008111156101d057600080fd5b8201836020820111156101e257600080fd5b8035906020019184600183028401116401000000008311171561020457600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192908035906020019064010000000081111561026757600080fd5b82018360208201111561027957600080fd5b8035906020019184600183028401116401000000008311171561029b57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290803590602001906401000000008111156102fe57600080fd5b82018360208201111561031057600080fd5b8035906020019184600183028401116401000000008311171561033257600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192908035906020019064010000000081111561039557600080fd5b8201836020820111156103a757600080fd5b803590602001918460018302840111640100000000831117156103c957600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192905050506109a9565b005b6104496004803603602081101561043357600080fd5b8101908080359060200190929190505050610ab5565b6040518080602001806020018060200180602001806020018060200187810387528d818151815260200191508051906020019080838360005b8381101561049d578082015181840152602081019050610482565b50505050905090810190601f1680156104ca5780820380516001836020036101000a031916815260200191505b5087810386528c818151815260200191508051906020019080838360005b838110156105035780820151818401526020810190506104e8565b50505050905090810190601f1680156105305780820380516001836020036101000a031916815260200191505b5087810385528b818151815260200191508051906020019080838360005b8381101561056957808201518184015260208101905061054e565b50505050905090810190601f1680156105965780820380516001836020036101000a031916815260200191505b5087810384528a818151815260200191508051906020019080838360005b838110156105cf5780820151818401526020810190506105b4565b50505050905090810190601f1680156105fc5780820380516001836020036101000a031916815260200191505b50878103835289818151815260200191508051906020019080838360005b8381101561063557808201518184015260208101905061061a565b50505050905090810190601f1680156106625780820380516001836020036101000a031916815260200191505b50878103825288818151815260200191508051906020019080838360005b8381101561069b578082015181840152602081019050610680565b50505050905090810190601f1680156106c85780820380516001836020036101000a031916815260200191505b509c5050505050505050505050505060405180910390f35b61070c600480360360208110156106f657600080fd5b8101908080359060200190929190505050610ef7565b6040518080602001806020018060200180602001806020018060200187810387528d818151815260200191508051906020019080838360005b83811015610760578082015181840152602081019050610745565b50505050905090810190601f16801561078d5780820380516001836020036101000a031916815260200191505b5087810386528c818151815260200191508051906020019080838360005b838110156107c65780820151818401526020810190506107ab565b50505050905090810190601f1680156107f35780820380516001836020036101000a031916815260200191505b5087810385528b818151815260200191508051906020019080838360005b8381101561082c578082015181840152602081019050610811565b50505050905090810190601f1680156108595780820380516001836020036101000a031916815260200191505b5087810384528a818151815260200191508051906020019080838360005b83811015610892578082015181840152602081019050610877565b50505050905090810190601f1680156108bf5780820380516001836020036101000a031916815260200191505b50878103835289818151815260200191508051906020019080838360005b838110156108f85780820151818401526020810190506108dd565b50505050905090810190601f1680156109255780820380516001836020036101000a031916815260200191505b50878103825288818151815260200191508051906020019080838360005b8381101561095e578082015181840152602081019050610943565b50505050905090810190601f16801561098b5780820380516001836020036101000a031916815260200191505b509c5050505050505050505050505060405180910390f35b60015481565b6040518060c001604052808781526020018681526020018581526020018481526020018381526020018281525060008060015481526020019081526020016000206000820151816000019080519060200190610a069291906112c3565b506020820151816001019080519060200190610a239291906112c3565b506040820151816002019080519060200190610a409291906112c3565b506060820151816003019080519060200190610a5d9291906112c3565b506080820151816004019080519060200190610a7a9291906112c3565b5060a0820151816005019080519060200190610a979291906112c3565b50905050600160008154809291906001019190505550505050505050565b606080606080606080610ac6611343565b6000808981526020019081526020016000206040518060c0016040529081600082018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610b7c5780601f10610b5157610100808354040283529160200191610b7c565b820191906000526020600020905b815481529060010190602001808311610b5f57829003601f168201915b50505050508152602001600182018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610c1e5780601f10610bf357610100808354040283529160200191610c1e565b820191906000526020600020905b815481529060010190602001808311610c0157829003601f168201915b50505050508152602001600282018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610cc05780601f10610c9557610100808354040283529160200191610cc0565b820191906000526020600020905b815481529060010190602001808311610ca357829003601f168201915b50505050508152602001600382018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610d625780601f10610d3757610100808354040283529160200191610d62565b820191906000526020600020905b815481529060010190602001808311610d4557829003601f168201915b50505050508152602001600482018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610e045780601f10610dd957610100808354040283529160200191610e04565b820191906000526020600020905b815481529060010190602001808311610de757829003601f168201915b50505050508152602001600582018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610ea65780601f10610e7b57610100808354040283529160200191610ea6565b820191906000526020600020905b815481529060010190602001808311610e8957829003601f168201915b5050505050815250509050806000015181602001518260400151836060015184608001518560a001518595508494508393508292508191508090509650965096509650965096505091939550919395565b6000602052806000526040600020600091509050806000018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610fa35780601f10610f7857610100808354040283529160200191610fa3565b820191906000526020600020905b815481529060010190602001808311610f8657829003601f168201915b505050505090806001018054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156110415780601f1061101657610100808354040283529160200191611041565b820191906000526020600020905b81548152906001019060200180831161102457829003601f168201915b505050505090806002018054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156110df5780601f106110b4576101008083540402835291602001916110df565b820191906000526020600020905b8154815290600101906020018083116110c257829003601f168201915b505050505090806003018054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561117d5780601f106111525761010080835404028352916020019161117d565b820191906000526020600020905b81548152906001019060200180831161116057829003601f168201915b505050505090806004018054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561121b5780601f106111f05761010080835404028352916020019161121b565b820191906000526020600020905b8154815290600101906020018083116111fe57829003601f168201915b505050505090806005018054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156112b95780601f1061128e576101008083540402835291602001916112b9565b820191906000526020600020905b81548152906001019060200180831161129c57829003601f168201915b5050505050905086565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061130457805160ff1916838001178555611332565b82800160010185558215611332579182015b82811115611331578251825591602001919060010190611316565b5b50905061133f9190611379565b5090565b6040518060c001604052806060815260200160608152602001606081526020016060815260200160608152602001606081525090565b61139b91905b8082111561139757600081600090555060010161137f565b5090565b9056fea265627a7a7231582006e05d73bc6bcbb7763fbd0d4a50d428eea080d36990a3d47731427e60848c4164736f6c63430005100032'  # Replace with actual Bytecode

        # Login Page
        self.login_frame = tk.Frame(self.root)
        self.username_label = tk.Label(self.login_frame, text="Username:")
        self.username_entry = tk.Entry(self.login_frame)
        self.password_label = tk.Label(self.login_frame, text="Password:")
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)

        self.username_label.pack()
        self.username_entry.pack()
        self.password_label.pack()
        self.password_entry.pack()
        self.login_button.pack()
        self.login_frame.pack(padx=20, pady=20)

        # Main Application Frame
        self.main_frame = None

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if (username == "admin" and password == "admin") or (username == "user1" and password == "user1") or (username == "user2" and password == "user2"):
            self.user = username
            self.login_frame.destroy()
            self.create_main_frame()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def create_main_frame(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True)

        self.tab_control = ttk.Notebook(self.main_frame)

        self.home_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.home_tab, text="Home")
        self.home_label = tk.Label(self.home_tab, text="Welcome to Blockchain App!", font=("Arial", 20), padx=20, pady=20)
        self.home_label.pack()

        self.metadata_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.metadata_tab, text="Metadata")

        self.blocks_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.blocks_tab, text="Blocks")
        self.tab_control.pack(expand=1, fill="both")

        self.block_labels = []
        self.create_block_labels()

        # Smart Contract Deployment Details Tab
        self.contracts_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.contracts_tab, text="Smart Contracts")
        self.contract_labels = []
        self.create_contract_labels()

    def create_block_labels(self):
        for label in self.block_labels:
            label.destroy()
        self.block_labels.clear()

        blocks = self.ref.get()
        if blocks:
            for block_index, (block_id, block_data) in enumerate(blocks.items(), start=1):
                block_label = tk.Label(self.blocks_tab, text=f"BLOCK {block_index}", font=("Arial", 12), padx=10, pady=10, relief="ridge")
                block_label.bind("<Button-1>", lambda event, idx=block_id: self.show_metadata_popup(idx))  # Bind click event
                block_label.pack(pady=5)
                self.block_labels.append(block_label)

    def create_contract_labels(self):
        for label in self.contract_labels:
            label.destroy()
        self.contract_labels.clear()

        contracts = self.ref.child('contracts').get()
        if contracts:
            for contract_index, (contract_id, contract_data) in enumerate(contracts.items(), start=1):
                contract_label = tk.Label(self.contracts_tab, text=f"BLOCK {contract_index}", font=("Arial", 12), padx=10, pady=10, relief="ridge")
                contract_label.bind("<Button-1>", lambda event, c_addr=contract_data['contract_address']: self.show_contract_popup(c_addr))
                contract_label.pack(pady=5)
                self.contract_labels.append(contract_label)

    def generate_rsa_keys(self):
        (public_key, private_key) = rsa.newkeys(2048)
        return private_key, public_key

    def strip_key(self, key):
        return key.replace('-----BEGIN RSA PRIVATE KEY-----', '').replace('-----END RSA PRIVATE KEY-----', '').replace('-----BEGIN RSA PUBLIC KEY-----', '').replace('-----END RSA PUBLIC KEY-----', '').replace('\n', '').strip()[:64]

    def serialize_keys(self, private_key, public_key):
        private_pem = self.strip_key(private_key.save_pkcs1().decode('utf-8'))
        public_pem = self.strip_key(public_key.save_pkcs1().decode('utf-8'))
        return private_pem, public_pem

    def sha3_hash(self, data):
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(data.encode('utf-8'))
        return keccak_hash.hexdigest()

    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code " + str(rc))
        client.subscribe("esp8266/metadata")

    def on_message(self, client, userdata, msg):
        try:
            metadata_json = msg.payload.decode('utf-8')
            metadata = json.loads(metadata_json)

            # Passkey Authentication Logic
            correct_passkey = "CIOT_123"
            if 'passkey' in metadata and metadata['passkey'] == correct_passkey:
                # Remove passkey from metadata to avoid storing it
                del metadata['passkey']

                device_id = metadata['device_id']
                mac_address = metadata['mac_address']
                firmware_version = metadata['firmware_version']

                self.store_metadata(device_id, mac_address, firmware_version)
            else:
                self.handle_authentication_failure()
        except Exception as e:
            print(f"Failed to process message: {e}")
            self.handle_authentication_failure()

    def handle_authentication_failure(self):
        messagebox.showerror("Connection Refused", "Invalid passkey. Connection refused.")
        self.root.destroy()

    def store_metadata(self, device_id, mac_address, firmware_version):
        private_key, public_key = self.generate_rsa_keys()
        private_pem, public_pem = self.serialize_keys(private_key, public_key)
        contract_address = self.sha3_hash(device_id + mac_address + firmware_version)

        metadata_dict = {
            'Device ID': device_id,
            'MAC Address': mac_address,
            'Firmware Version': firmware_version,
            'Public Key': public_pem,
            'Private Key': private_pem,
            'Contract Address': contract_address
        }

        metadata_json = json.dumps(metadata_dict)
        print(f"Metadata JSON: {metadata_json}")

        # Store metadata in Firebase
        try:
            new_block_ref = self.ref.push(metadata_dict)
            print("Firebase push successful.")
        except Exception as e:
            print(f"Firebase push failed: {e}")

        # Deploy smart contract
        tx_hash, tx_receipt = self.deploy_smart_contract(metadata_dict)
        metadata_dict['Contract Address'] = tx_receipt.contractAddress

        # Update metadata with actual contract address
        self.ref.child(new_block_ref.key).update({'Contract Address': tx_receipt.contractAddress})

        # Store contract details in Firebase
        contract_data = {
            'transaction_hash': tx_hash,
            'contract_address': tx_receipt.contractAddress,
            'block_number': tx_receipt.blockNumber,
            'block_timestamp': self.w3.eth.get_block(tx_receipt.blockNumber).timestamp,
            'account': self.account,
            'gas_price': self.w3.eth.gas_price,
            'total_cost': tx_receipt.gasUsed * self.w3.eth.gas_price
        }

        try:
            new_contract_ref = self.ref.child('contracts').push(contract_data)
            print("Contract details stored in Firebase.")
        except Exception as e:
            print(f"Failed to store contract details: {e}")

        # Append metadata to metadata.txt
        with open(f"{self.user}_metadata.txt", "a") as file:
            file.write(metadata_json + "\n")

        self.create_block_labels()
        self.create_contract_labels()
        messagebox.showinfo("Success", f"Metadata stored successfully! Private Key: {private_pem}")

    def deploy_smart_contract(self, metadata):
        contract = self.w3.eth.contract(abi=self.abi, bytecode=self.bytecode)
        tx_hash = contract.constructor().transact({'from': self.account})
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Smart Contract deployed at: {tx_receipt.contractAddress}")
        return tx_hash.hex(), tx_receipt

    def show_metadata_popup(self, block_id):
        block_data = self.ref.child(block_id).get()
        if block_data:
            # Print the block_data to check what keys are present
            print("Block data keys:", block_data.keys())

            private_key = simpledialog.askstring("Private Key", "Enter the private key to access metadata:")
            if 'Private Key' in block_data and private_key == block_data['Private Key']:
                metadata_text = "\n".join([f"{key}: {value}" for key, value in block_data.items()])
                messagebox.showinfo(f"Block {block_id} Metadata", metadata_text)
            else:
                messagebox.showwarning("Error", "Invalid private key.")
        else:
            messagebox.showwarning("Error", f"No data found for Block {block_id}")

    def show_contract_popup(self, contract_address):
        contract_data = self.ref.child('contracts').order_by_child('contract_address').equal_to(contract_address).get()
        if contract_data:
            for contract_id, data in contract_data.items():
                address = simpledialog.askstring("Contract Address", "Enter the contract address to access contract details:")
                if address == contract_address:
                    contract_text = "\n".join([f"{key}: {value}" for key, value in data.items()])
                    messagebox.showinfo(f"Contract {contract_id} Details", contract_text)
                    return
            messagebox.showwarning("Error", "Invalid contract address.")
        else:
            messagebox.showwarning("Error", f"No data found for Contract {contract_address}")

if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainApp(root)
    root.mainloop()

