# coding=utf-8
import hashlib #hash 값을 구하기 위한 hashlib 이란 모듈 가져옴
import json #json 형식을 취하기 위해 모듈 가져옴
from time import time # time 이란 모듈로부터 time 이란 이름 속성 가져옴
from urllib.parse import urlparse # urllib.parse 이란 모듈로부터 urlparse 라는 이름 속성 가져옴
from uuid import uuid4 # uuid 란 모듈로 부터 uuid4 라는 이름 속성 가져옴

import requests # requests 라는 이름의 모듈 가져옴
from flask import Flask, jsonify, request #flask 란 모듈로부터 Flask, jsonify, request 란 이름 속성 가져옴


class Blockchain:
    """
    class Blockchain 은 Tx들을 담거나 새로운 Block 들을 생성해서 chain에 추가하는 등
    chain들을 관리하는 역할을 한다.

    """
    def __init__(self):
        """
        생성자의 역할을 한다. 즉 객체를 생성할 때 자동으로 호출됨.
        """
        self.current_transactions = [] # Tx 들이 들어갈 배열 생성
        self.chain = [] # chain 들이 들어갈 배열 생성
        self.nodes = set() # node 들이 들어갈 집합. 중복을 허용하지 않는 특징이 있다.

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100) # 코인이 최초에 실행될 때 만들어질 genesis block

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address) # parsed_url 이란 변수에 address 란 값을 넣은 urlparse 모듈을 지정
        if parsed_url.netloc: # 만약 parsed_url 이 netloc 형식 을 지니면 그 값을 nodes 에 삽입
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path: # 만약 parsed_url 이 netloc 형식이 아니라 path 형식이면 그 값을 nodes 에 삽입
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL') # parsed_url 이 위의 두 조건을 모두 만족하지 않으면 에러메세지 호출


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0] # last_block 이란 변수는 chain 배열의 첫번째 값, 최근 블록을 가르키는 변수
        current_index = 1 # 현재 블록이 몇 번째인지 가르쳐 주는 변수

        while current_index < len(chain): # current_index 가 chain 배열의 길이보다 같거나 길어질 때 까지 밑의 과정을 실행
            block = chain[current_index] # block 은 chain 배열의 current_index 번째로 삽입
            print(f'{last_block}') # 위 last_block 값 print
            print(f'{block}') # 위 block 값 print
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block) # last_block_hash 값은 위 last_block 의 hash 이다.
            if block['previous_hash'] != last_block_hash:
                return False
            # 만약 block 의 json 파일 내용 중 previous_hash 의 값이 last_black_hash 와 다르면 false

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1
            # 위 과정을 통과하면 last_block 이 block 이 되고 current_index 값 1 증가 그리고 반복

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes #neighbours 는 nodes 다
        new_chain = None # new_chain 변수 생성

        # We're only looking for chains longer than ours
        max_length = len(self.chain) # max_length 변수는 chain 의 길이

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            # requests 모듈을 이용, f'http://{node}/chain' 값 요청함

            if response.status_code == 200: # 응답이 200 즉 정상적이면
                length = response.json()['length'] # length 값은 응답한 json 파일의 length 값
                chain = response.json()['chain'] # chain 값은 응답한 json 파일의 chain 값

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain


        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        # 기본적인 block 의 정보들
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        # chain 배열에 block 의 값을 뒤에 추가
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        # current_transactions 의 값에 입력된 sender, recipient, amount 값 입력
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        # last_block 의 index 값에 1 추가
        return self.last_block['index'] + 1

    # last_block 은 chain 배열에서 뒤에서 두 번째 값
    @property
    def last_block(self):
        return self.chain[-1]


    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode() # json 형식으로 변경
        return hashlib.sha256(block_string).hexdigest() # hashlib 모듈을 이용한 hash 값

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof'] # last_proof 는 last_block 의 proof 값
        last_hash = self.hash(last_block) # last_hash 는 last_block 의 hash 값

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1
        # valid_proof 가 true 가 될때 까지 proof 값 1씩 증가

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
        # sha256 방식과 hex 방식을 이용해 만든 해쉬값의 뒤의 4자리로 난이도이다

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

# Flask Routing, /mine url 접속시 mine 함수 GET 방식으로(비 암호화 url 적힘) 실행
@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

# url /transactions/new 접속시 new_transactions() POST(url 안보임) 실행
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

# url /chain 접속시 full_chain() GET 방식으로 실행
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

# url /nodes/register 접속시 register_nodes() POST 방식으로 실행
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

# url /nodes/resolve 접속시 consensus() GET 방식으로 실행
@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


if __name__ == '__main__': # 만약 이 파일이 실행이 된다면
    from argparse import ArgumentParser # argparse 모듈에서 ArgumentParser 을 끌어와서

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    # port 의 값을 자동으로 입력받아서 넣어주는 방식

    app.run(host='0.0.0.0', port=port)
    # app 을 127.0.0.1:5000 과 같은 형식으로 실행한다.