import network_3_0 as Network
import argparse
from time import sleep
import hashlib

class Flags:
    ACK = 0
    NACK = 1

    @staticmethod
    def create_ack(sequence_no):
        return "10" + str(sequence_no)

    @staticmethod
    def create_nack(sequence_no):
        return "01" + str(sequence_no)

    @staticmethod
    def is_ack(str):
        return str[0] == '1'

    @staticmethod
    def is_nack(str):
        return str[1] == '1'

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32
    flags_length = 3
        
    def __init__(self, seq_num, msg_S = "", flags = "000"):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.flags = flags

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        flags_begin_index = Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length
        flags = str(byte_S[flags_begin_index : flags_begin_index + Packet.flags_length ])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length+Packet.flags_length :]
        return self(seq_num, msg_S, flags)

    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.flags) + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.flags+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.flags + self.msg_S

    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        flags_begin_index = Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length
        flags_S = str(byte_S[flags_begin_index : flags_begin_index + Packet.flags_length])
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length+Packet.flags_length:]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+flags_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

    @staticmethod
    def create_ack(sequence_number, ack_no):
        return Packet(sequence_number, flags=Flags.create_ack(ack_no))

    def is_ack(self):
        return Flags.is_ack(self.flags)

    def get_ack_no(self):
        return int(self.flags[-1])

class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = ''
    send_packet = None

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
        self.state = 0
    
    def disconnect(self):
        self.network.disconnect()

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def receive_packet(self):
        # keep extracting packets - if reordered, could get more than one
        while True:
            byte_S = self.network.udt_receive()
            self.byte_buffer += byte_S

            # check if we have received enough bytes
            if (len(self.byte_buffer) < Packet.length_S_length):
                continue  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                continue  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string
            packet_contents = self.byte_buffer[0:length]

            # update the buffer to remove the currently read packet
            self.byte_buffer = self.byte_buffer[length:]

            if Packet.corrupt(packet_contents):
                return None

            p = Packet.from_byte_S(packet_contents)
            return p
    
    def rdt_3_0_send(self, msg_S):
        current_seq = self.seq_num
        send_packet = Packet(current_seq, msg_S)
        print("SENDER: Sending packet with seq %d" % self.seq_num)

        while current_seq == self.seq_num:
            self.network.udt_send(send_packet.get_byte_S())
            print("SENDER: Sent packet with seq %d" % self.seq_num)
            print("SENDER: Waiting for ack to %d" % self.seq_num)
            packet = self.receive_packet()
            if packet is None:
                print("SENDER: Received packet that was corrupted")
            elif packet.is_ack() and packet.get_ack_no() != self.seq_num:
                print("SENDER: Received ack for old packet, resending current packet")
            elif packet.is_ack() and packet.get_ack_no() == self.seq_num:
                print("SENDER: Seq %d was successfully acked" % self.seq_num)
                self.seq_num = self.inv_seq_num()
                break
            elif packet.seq_num != self.seq_num:
                print("SENDER: Receiver behind sender, sending ack")
                self.network.udt_send(Packet.create_ack(self.seq_num, packet.seq_num).get_byte_S())


    def rdt_3_0_receive(self):

        current_seq = self.seq_num

        while current_seq == self.seq_num:
            packet = self.receive_packet()
            print("RECEIVER: Receiving packet")
            if packet is None:
                # packet is corrupt
                print("RECEIVER: Received corrupt packet, sending ack for last received sequence number")
                self.network.udt_send(Packet.create_ack(self.seq_num, self.inv_seq_num()).get_byte_S())
            elif packet.seq_num != self.seq_num:
                # packet has sequence number we don't want
                print("RECEIVER: Received packet with incorrect sequence number %d, desired %d, sending ack" % (packet.seq_num, self.seq_num))
                self.network.udt_send(Packet.create_ack(self.seq_num, packet.seq_num).get_byte_S())
            else:
                # packet has data matching our desired sequence number
                data_S = packet.msg_S
                print("RECEIVER: Successfully received packet with seq '%d' with response %s" % (self.seq_num, data_S))
                self.network.udt_send(Packet.create_ack(self.seq_num, packet.seq_num).get_byte_S())
                print("RECEIVER: Sending ack for sequence number %d" % packet.seq_num)
                self.seq_num = self.inv_seq_num()
                return data_S

    def inv_seq_num(self):
        return 0 if self.seq_num == 1 else 1


if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        