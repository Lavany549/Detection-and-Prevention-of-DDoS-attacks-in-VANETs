# Detection and Prevention of DDoS attacks in VANETs

VANET transmission includes many types of data packets such as traffic conditions, distress signals (eg. accident, brake failure, etc), situation awareness, etc.

They are vulnerable to cyber attacks, especially Distributed Denial of Service attack, where the attacker can compromise nodes inside the networks to occupy the resources and impact communication. 


### Install

  This project requires python 3.9.15, and the following python libraries installed:

   + ###### [Numpy](https://numpy.org/)
   + ###### [Scapy](https://scapy.net/)
   + ###### [Pandas](https://pandas.pydata.org/)

  Also require the following softwares to be installed
   
   + ###### Git Core : 
     ```sudo apt-get install git-core```
     
   + ###### Controller : [MiniNet](https://noxrepo.github.io/pox-doc/html/)
     ```git clone git://github.com/mininet/mininet```
     
     ```sudo apt-get install mininet```
     
   + ###### Emulator : [POX](https://noxrepo.github.io/pox-doc/html/)
     ```../mininet/util/install.sh -p```

### Code
   * Copy the *l3_ddosMitigationFinal1.py* and *detectionUsingEntropy.py* files in *.../pox/pox/forwarding/* folder. 

   * Copy the *trained_model.joblib , entropy.joblib* file in *.../pox/* folder. 
  
   You will also be required to use the *flooding.py* , *traffic.py* and *attack.py* Python files for generating flooding, traffic and attack packets respectively . The file *detectionUsingEntropy.py* is used to calculate the entropy. 
 

### Run
  #### Step 1: Network setup and Traffic Generation(Done for data which is not necessary now )
  * #### Terminal 1 : Starting the POX Controller
      Open the terminal and start the POX controller with modified l3_learning component (l3_ddosMitigationFinal1.py) which is used to run the POX's learning switch. Additional functions such as Statisic collection, Entropy computation and Machine Learning classifier, are added here
     
     ``` $ cd pox ```
     
     ``` $ sudo python3 pox.py forwarding.l3_ddosMitigationFinal1  ```
   
  * #### Terminal 2 : Building Network Topology

     Open another tab of terminal and run

     ``` $ sudo mn --switch ovs --topo tree,depth=2,fanout=8 --controller=remote,ip=127.0.0.1 ```
  
     A tree network topology with depth of 2 and fanout of 8 is built and connected to the remote controller running at 127.0.0.1. The topology built is displayed 
  
  * #### Information about all nodes (Optional)

     To find all the Properties of Nodes and Switches , Go to Terminal 2 and run   
   
     ```mininet > dump ```

     All the Information will be displayed
   
  * #### Testing Connectivity (Optional)
  
     From Terminal 2  run
   
     ``` mininet > xterm h1```

     An another terminal lets say Terminal 3 is opened for *node h1* , Now run 
   
     ```# ping 10.0.0.2 -c 4``` 
   
     This shows the data of packet if connected successfully.

  #### Step 2: Integrating the Utilities in the Controller
  * From Terminal 2 run
  
    ``` mininet > xterm h1```

    Another terminal pops up lets say Terminal 3 is opened for *node h1* , Now run
  
    ```# python3 traffic.py -s 4 -e 65```
  
    This will produce the required traffic data into the network
  
  * From Terminal 2 open another *node h2*,

    ```mininet > xterm h2```
  
    Another terminal pops up lets say Terminal 4 is opened for *node h2* , Now run

    ```# python3 attack.py 10.0.0.6```
  
    This will run an attack on the Node 10.0.0.6

  * From Terminal 2 open another *node h3*,

    ```mininet > xterm h3```
  
    Another terminal pops up lets say Terminal 5 is opened for *node h3* , Now run

    ```# python3 flooding.py```
  
    This will produce the flooding packets into the network.
  
  * Upon starting each traffic, the resulting entropy calculation and classifier outputs can be found in Terminal 1. 
  * The traffic can be ended by pressing **Ctrl + Z** in their respective terminal

