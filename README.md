# SimpleBlockchain
A Distributed Systems project that builds a blockchain from data read from files.

## Technologies Used
Java: openjdk version "11.0.11"

## Description
Three processes work together to verify data for a blockchain. Once all three processes are running, they each read in data from their own file and then shares the data with the other two processes. The data is transfered into an unverified block which is added into a list with the rest of the unverified blocks. The processes then begin attempting to verify data so that it can be added to the blockchain. 

A processes will concatenate the block data, the previous verified block's winning hash value, and a randomly generated value. The concatinated data is hashed and the hash is checked for validity. If the hashed value meets some preset criteria (such as being divisible by 10000 for example), then the hash is considered valid, and the random value is considered one that verifies the block. The random value is stored with the verified block as a correct guess and the block has now been verified. The verified block is stored in a list the processes maintains, and then shared with the other two processes so that they can update their respective lists. All processes then proceed to carry out this process for the next unverified block.

As each block is verified, it is also added to a file called BlockchainLedger.json so that when the data is done being verieid, the completed blockchain can be viewed.

A part of this project also dealt with encryption. Each process generates a public and private RSA key that it shares with the other two processes. When a process verifies a block, it signs the block before sharing it so that the others can verify the signature using the shared public keys. 


## Running the Application
A version of the Java JDK will need to be downloaded and installed. This current version of the blockchain program was tested using Java 11. All repository files also need to be downloaded and placed in the same directoy.

Running the compile.bat file, followed by the Start.bat file, will compile and run the program.

Alternatively, the program can be compiled and run manually.The three proccess are started using the same java class. All of the code and classes are in the same java file, Blockchain.java, per the instructions of the professor who taught the class. The java classes needs to be compiled using the following command entered on a command line:

```
javac -cp "gson-2.8.2.jar" Blockchain.java
```

To start the program, the following three commands need to be run in order, in three different command prompt windows:

```
java -cp ".;gson-2.8.2.jar" Blockchain 0
java -cp ".;gson-2.8.2.jar" Blockchain 1
java -cp ".;gson-2.8.2.jar" Blockchain 2
```

Blockchain 2 starting is the trigger for the application to begin processing the data.

Once the initial round of guessing is done, a prompt is presented to the use with additional options that can be done on the completed blockchain. The most interesting of these options allows processing additional unverified data:

```
R [filename]
```

An additional file was added to the repository, ExtraInput.txt. Typing in "R ExtraInput.txt" from any of the three command prompts, will cause the processes to read in the data from this extra file, share the data, and then begin the process over again.  

The other prompt options mainly have to do with verifying that signautes for blocks were done correctly, and that they blockchain was assembled correctly.


## The Data
BlockInput0.txt, BlockInput1.txt, and BlockInpout2.txt are the files that the processes read data from. Each line in these files is another unverified block whose attributes are seperated by spaces. Each line currently has 7 attributes and that's exactly how many the program reads in. More lines can be added but they must have 7 pieces of information seperated by spaces. 

