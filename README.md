# Detection and Prevention of DDoS attacks in VANETs

VANET transmission includes many types of data packets such as traffic conditions, distress signals (eg. accident, brake failure, etc), situation awareness, etc.

They are vulnerable to cyber attacks, especially Distributed Denial of Service attack, where the attacker can compromise nodes inside the networks to occupy the resources and impact communication. 


### Install

 This project requires python 3.9.15, and the following python libraries installed:

  ###### [Numpy](https://numpy.org/)
  ###### [Scapy](https://scapy.net/)
  ###### [Pandas](https://pandas.pydata.org/)

 Also require the following softwares to be installed

  ###### Emulator : [POX](https://noxrepo.github.io/pox-doc/html/)
  ###### Controller : [MiniNet](https://noxrepo.github.io/pox-doc/html/)

### Code

 Template code is provided in the *l3_ddosMitigationFinal1.py* python file. You will also be required to use the *flooding.py* , *traffic.py* and *attack.py* Python files for generating flooding, traffic and attack packets respectively . The file *detectionUsingEntropy.py* is used to calculate the entropy. 

 The data packets sent from each of the traffic is collected and saved as data. This data is used to train the KNN classifier and is saved as *trained_model.joblib* file. This file can directly be used in *l3_ddosMitigationFinal1.py* for predicting whether the present packet belongs to **attack** or  **non-attack** label.


### Run

 #### Step 1: Network setup and Traffic Generation(Done for data which is not necessary now )

 #### Terminal 1 : Starting the pox Controller

  Open the terminal and start the POX controller with modified l3_learning component (l3_ddosMitigationFinal1.py) which is used to run the POX's learning switch.Additional functions such as Statisic collection, Entropy computation and Machine Learning classifier, are added here

  ``` $ cd pox ```

  ``` $ sudo python3 ./pox forwarding.l3_ddosMitigationFinal1  ```

  then enter your password.

 #### Terminal 2 : Building Network Topology

  Open another tab of terminal and run

  ``` $ sudo mn --switch ovs --topo tree,depth=2,fanout=8 --controller=remote,ip=127.0.0.1 ```

  A tree network topology with depth of 2 and fanout of 8 is built and connected to the remote controller running at 127.0.0.1. The topology built is displayed 


 #### Information about all nodes (Optional)
   To find all the Properties of Nodes and Switches , Go to Terminal 2 and run

    ```mininet > dump ```

  All the Information will be displayed


 #### Testing Connectivity (Optional)

  From Terminal 2  run

  ``` mininet > xterm h1```

  An another terminal lets say Terminal 3 is opened with *node h1* , Now run 

  ```# ping 10.0.0.2 -c 4``` 

  This shows the data of packet if connected successfully.Close this node if connected successfully.

 #### Step 2: Integrating the Utilities in the Controller

  From Terminal 2 run

  ``` mininet > xterm h1```

  Another terminal pops up lets say Terminal 3 is opened with *node h1* , Now run

  ```# python3 traffic.py -s 4 -e 65```

  This will run the traffic with 10.0.0.4 to 10.0.0.64 hosts as destination Nodes

  Now the mininet starts sending the traffic.

  From Terminal 2 open another *node h2*,

  ```mininet > xterm h2```

  Another terminal pops up lets say Terminal 4 is opened with *node h2* , Now run

  ```# python3 attack.py 10.0.0.6```

  This will run an attack on the Node 10.0.0.6

  Now Go to Terminal 1 and check whether the results are displayed.
  If yes, stop Terminal 2 by *Ctrl + Z* and stop the Terminal 3 and 4 now using the same command *Ctrl + Z*.

  You can observe the results in Terminal 1.

### Data

 We ran the traffic for Normal traffic (traffic.py) , Flooding traffic (flooding.py) and attack traffic (attack.py) and collected around 7000 samples.

 We trained the model with the follwing input :

  * Source port number
  * Destination Port number	
  * IP Protocol	
  * Byte Count	
  * Source IP First Octet	
  * Source IP Second Octet	
  * Source IP Third Octet
  * Source IP Fourth Octet	
  * Destination IP Last Octet

 and Output label as **Attack** or **Non-attack**

 We trained KNN classifier which gave us 98.6% accuracy and saved it as *trained_model.joblib* which can be used directly in *l3_ddosMitigationFinal1.py*.
