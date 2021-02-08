



import ctypes   # This Library will be used to get pointed inside multops.


#   This program is meant to simulate and demonstrate the Multops Data structure.
#   We have defined two classes, (i) The Multops Data Structure itself, (ii) a class MultopsTree representing a node of the Multops tree as described in the research paper.

#   In the real world when Multops is implemented, it will be called by the router when handling a packet.
#   Multops has only two interfaces which the router will utilizes.
#   Thus we have created two methods in the Multops class Forward_Packets_Interface, and Forward_Packets_Interface which we will use to demonstrate the Multops data structure.

#   We highly recommend going to the driver code first and commenting out each section to see how Multops is performing.

#   One very important thing to note is that in this presentation whenever we are passing i.p address into methods we will be passing them as lists, i.e. 192.168.1.10 will be passed as [192, 168, 10, 10]


class Multops:
    def __init__(self , r_min, r_max):  # r_min and r_max are the two parameters given by us to by which it determines weather to drop a packet or not.

        self.root = MultopsTreeNode(None)   # This the root node of the Multops Tree. represented by a MultopsTreeNode object. "None" parameter means that this tree node has no parent.
        
        
        self.beta = 0.95    # This is used to tune the sensititvity of Multops. The number of values to be averaged over = ( 1 / 1-beta ) in our exponentially weighted mean average, so beta of 0.95 results in an average of last 20 values.
        
        self.packets_per_second_threshold = 50      # This is the max acceptable packets per second before a child node is created in any tree.
        
        self.r_max = r_max  # These two attributes are ratio values used to detect and drop packets from malicious hosts.
        self.r_min = r_min
        
        self.packets_routed = 0     # These three attributes are for demonstration puposes only, and keep track of Multops activity.
        self.victim_packets_dropped = 0
        self.attacker_packets_dropped = 0


    # Below are the two manin Multops interface methods

    def Forward_Packets_Interface(self, number_of_packets, address):    # This is where forward packets are fed to Multops along with the relevant ip address.
        
        # When the router want to detemine how to handle a forward packet, it calls this method. 
        # The router gives multops a forward address and the current transmission rate of that address then this method determines weather to drop or route the packet. 

        to_rate, from_rate, is_deepest = self.update(address, number_of_packets , True)     # the update method returns the revevant transmission rates of that address and a bool which tells if the address is full mapped in the tree and ready to be dropped.
        
        if is_deepest:  # if we have enough information gathered about the specified address in our tree we will call RatioBlocker to give us a bool if we want to drop or not.
            if_to_block = self.RatioBlocker(to_rate, from_rate)     # Ratio blocker determines a bool which is fed back to the router.
            return if_to_block
        
        else:   # if we do not have enough information on the address we route the packet.
            self.packets_routed += 1
            return True
        

    def Backward_Packets_Interface(self, number_of_packets, address):

        # This method is performing essintitally the same task but it is called by the router for reverse packets.
        
        to_rate, from_rate, is_deepest = self.update(address, number_of_packets , False)
        
        if is_deepest:
            if_to_block = self.RatioBlocker(to_rate, from_rate)
            return if_to_block
        
        else:
            self.packets_routed += 1
    
    
    def RatioBlocker(self, to_rate, from_rate):

        # This method is given the transmission rates and it calcultes weather to drop or not based on the parameters r_min and r_max set during the initilization of Multops.

        try:
            calculated_ratio = to_rate/from_rate    # calculate the ratio of the to_rate and from_rate and compare it with given parameters.

        except ZeroDivisionError:   # if either of the two values are 0 the determine if a there is a victim or an attacker, either way we drop the packet.
            
            if from_rate == 0:
                self.attacker_packets_dropped += 1
                return 'The given address is attacking someone, Dropping Packet'    # This will be returned as a bool when implemting in a router but here we just return strings to give an expliantion of whats going.

            elif to_rate == 0:
                self.victim_packets_dropped += 1
                return 'Victim is being attacked, dropping packet'

        
        if self.r_max > calculated_ratio > self.r_min:  # if calculated is normal, then route the packet.
            self.packets_routed += 1
            return 'Normal transmission rate, packet is routed.'

        elif calculated_ratio > self.r_max:
            self.attacker_packets_dropped += 1
            return 'The given address is attacking someone, Dropping Packet'
            
        elif calculated_ratio < self.r_min:
            self.victim_packets_dropped += 1
            return 'Victim is being attacked, dropping packet'
    


    def update(self, address, packets_per_second, fwd): # i.p address is passed as a list and other parametersd are determined by Multops interface method which is calling this method.
        
        # This method maintains the Multops Tree.
        # (i) It updates relevant transmission rates.
        # (ii) It creates new table nodes when nessary based on transmission rates.
        # (iii) It returnes the current to_rate and from_rate of the given address and if it is elegibble to be dropped.

        table = self.root.table     # select Multops root_node's table.
        
        for prefix in address:  # iterate over each prefix in the ip address.
            
            record = table[prefix]  # get the record of the current pprefix in the current table.
            


            # The to_rate and from_rate are exponentially wighted moving averages of previous to_rate and from_rate, currently we have a self.beta = 0.95 which means we are averaging over last 20 rates.
                        
            if fwd: # if it is a forward packet then update the to-rate
                record[0] = (self.beta)*(record[0]) + ((1 - self.beta) * packets_per_second)
            
            else:   # else update the from-rate.
                record[1] = (self.beta)*(record[1]) + ((1 - self.beta) * packets_per_second)  
            
            if not record[2]:   # if there is no child in the current record, then break the loop.
                break
            else:
                table = record[2].table     # if there is a child then assume the table of that child. and updte relevant records in the next iteration.
        
        
        is_deepest_node = False

        try:    # this is meant to intentionaally ignore index error when the record is not in the lowest level of the tree.

            is_deepest_node = record[2].check_if_deepest(self.root, address)    # check if the current record is node in the lowest level of the tree.
        
        except:
            pass

        if record[0] > self.packets_per_second_threshold and not is_deepest_node:
            record[2] = MultopsTreeNode(id(record))  # create a child node in the record if the to-rate has exceeded the set packets_per_second_threshold and the current record is not the deepest node.

        elif record[1] > self.packets_per_second_threshold and not is_deepest_node:    
            record[2] = MultopsTreeNode(id(record))  # create a child node in the record if the from-rate has exceeded the set packets_per_second_threshold and the current record is not the deepest node.

        
        return record[0], record[1], is_deepest_node


    def Summary(self):  # This is demonstration method only, not meant to be implemented in a real router.
        print(f'{self.packets_routed} packets were sucessfully routed.')
        print(f'{self.victim_packets_dropped} packets were dropped because multops detected a victim was being attacked.')
        print(f'{self.attacker_packets_dropped} packets were dropped because multops detected an attacker was attacking.')




class MultopsTreeNode:  # This is the class which represents a node in the multops tree.
    
    def __init__(self, parent_node_location):
        self.table = [[0, 0, False] for each in range(256)]     # Each of the 256 records contains [to_rate, from_rate, pointer to child_node]
        self.table.append(parent_node_location)    # Each node of the tree also has a pointer to it's parent node.

    def return_parent_pointer(self):
        return ctypes.cast(self.table[256], ctypes.py_object).value    # return a refrence to the parent node object by using ctypes, we know its not very elegant but works.

    def check_if_deepest(self, tree_to_check, address):
        if ctypes.cast(self.table[256], ctypes.py_object).value[2] == tree_to_check.table[address[0]][2].table[address[1]][2].table[address[2]][2].table[address[3]][2]:    # checks if the parent object is in the second last level of the multops tree, i.e. the current node is a deepsest node.
            return True
        else:   # current node is not a deepest node in the tree so return False.
            return False

###############################################################################################################################################################
###############################################################################################################################################################


#   To demonstrate the algorithm we will be creating an instance of multops with a minimum and maximium transmission ratio. The entire code is reuseable and we only have to set these two paramerts when reusing the code inside a real router.
#   We will act as the router that multops is implemented on, and we will give data to Multops as a router.
#   Then we will check how many packets of a our specified address has Multops decide  route or drop.


#   Then we will test diffrent scenarios in which:

#   (i) We will give the two multops interfacs packets and an address for a range of time.
#   (ii) Multops will store what it decided to do woth the packet and provided information.
#   (iii) Finally we check what multops decided.
#   (iv) at any time you can check the state of the multops root tree using "print(m.root)"


m = Multops(0.66, 2.5)  # create a Multops data structure with 
address = [130, 168, 120, 10]   # This will be the i.p. addred used to test, it is the same as in the reearch papaer.
val = 500   # This is the rate of packects per second used throughout the testing process.

###############################################################################################################################################################

#   Please uncomment below code to test Multops and its response.


# for i in range(100):
#     m.Forward_Packets_Interface(val, address)   
#     m.Backward_Packets_Interface(val, address)   # i.e. same amount of packets are being sent and recieved.

# m.Summary()

###############################################################################################################################################################

#   Please uncomment below code to test Multops and its response.


# for i in range(50):
#     m.Forward_Packets_Interface(val, address)   # i.e. packets are outoging with no response coming back.

# m.Summary()




###############################################################################################################################################################

#   Please uncomment below code to test Multops and its response.


# for i in range(50):
#     m.Backward_Packets_Interface(val, address)   # i.e. packets are incoming with no response given back.
    
# m.Summary()




###############################################################################################################################################################

#   Please uncomment below code to test Multops and its response.


# for i in range(100):
#     m.Forward_Packets_Interface(val * 2.6, address)    # i.e. the outgoing packts are 2.6 times more than the incoming packets
#     m.Backward_Packets_Interface(val, address)

# m.Summary()




###############################################################################################################################################################

#   Please uncomment below code to test Multops and its response.


# for i in range(100):
#     m.Forward_Packets_Interface(val, address)
#     m.Backward_Packets_Interface(val * 3, address)      # i.e. the incoming packets are 3 times more than the outgoing packets 

# m.Summary()