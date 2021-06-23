//Blockchain.java

// Louis Rivera
// Blockchain Project

/*
The following sources were taken from BlockJ.java since the security code is taken from there.

The web sources:
https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
*/


/*
The following sources are from BlockInputG.java, although I'm not sure that I used much code from there.
The web sources:

Reading lines and tokens from a file:
http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
Good explanation of linked lists:
https://beginnersbook.com/2013/12/linkedlist-in-java-with-example/
Priority queue:
https://www.javacodegeeks.com/2013/07/java-priority-queue-priorityqueue-example.html

*/



// These were sources that I found to help with certain parts of the project. 

// https://www.javatpoint.com/java-get-current-date
// https://stackoverflow.com/questions/4216745/java-string-to-date-conversion

// Links for sending keys:
// https://stackoverflow.com/questions/7733270/java-public-key-different-after-sent-over-socket
// https://stackoverflow.com/questions/2411096/how-to-recover-a-rsa-public-key-from-a-byte-array
// https://stackoverflow.com/questions/1176135/socket-send-and-receive-byte-array

/*
   To compile: 
   javac -cp "gson-2.8.2.jar" Blockchain.java
   
   To run, the following commands need to be done in order, each in a seperate command prompt:
   java -cp ".;gson-2.8.2.jar" Blockchain 0
   java -cp ".;gson-2.8.2.jar" Blockchain 1
   java -cp ".;gson-2.8.2.jar" Blockchain 2
   
   
   The last command starts the three processes corrdinating and solving the blockchain.
   The processes begin trading public keys, and then trading blocks that are read in from three files.
      BlockInput0.txt
      BlockInput1.txt
      BlockInput2.txt
   
   The final blockchain ledger will be output to the file BlockchainLedger.json.
   Once the processes are done solving the blockchain for the initial set of data,
   a list of commands will be displayed on each console that will allow additional commands
   to be sent to the processes.
   
      R [fileName] - Read in more data from the supplied file
      C - Get the count of how many blocks each process has solved
      L - List each block that is in the ledger
      V - Verify the blockchain, checking that the winning hash is valid agains the previous hash
      V threshold - Verify the block hash was under the guess threshold
      V hash - Verify the block winning hash was signed
      V signature - Verify the block ID was signed
*/



import java.util.*;
import java.util.concurrent.*;
import java.io.*;

import java.lang.InterruptedException;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import java.net.*;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Blockchain {

   public static PrintStream out = System.out;
   public static int processID = 0;
   public static String serverName = "localhost";
   
   // This is the guessThreshold used by the miner later on to check if a hash is a winning hash.
   public static int guessThreshold = 5000;
   
   // Initially, I had envisioned keeping track of each thread that was created so that when the program was over,
   // the starting process could shut each thread down. I read though that Thread.stop() is depricated and shouldn't
   // be used so I decided against it.
   private static ArrayList<Thread> activeThreads;
   
   public static void main(String[] args) {

      if(args.length > 0) {
      
         try {         
            processID = Integer.parseInt(args[0]);
         }
         catch(NumberFormatException nfe) {
            System.out.println("Invalid argument to process.");
            System.out.println(args[0] + " could not be parsed to an integer.");
            System.out.println("Default processID of 0 being used.");
            processID = 0;
         }
      }

      
      System.out.println("Current processID : " + processID);
      String inputFileName = "BlockInput" + processID + ".txt";
      System.out.println("Retrieving: " + inputFileName);
      ArrayList<Block> blockDataList = DataCollector.retrieveLedgerFromFile(inputFileName);
      
      
      try {
         File file = new File("BlockchainLedger.json");
         file.delete();
      }
      catch(Exception e) {
         System.out.println(e);
      }
      
      
      // Start up the servers listening for different types of data
      activeThreads = new ArrayList<Thread>();
      
      KeyServer keyServer = new KeyServer(processID);
      startServer(keyServer);
      
      UnverifiedBlockServer unverifiedBlockServer = new UnverifiedBlockServer(processID);
      startServer(unverifiedBlockServer);
      
      VerifiedBlockServer verifiedBlockServer = new VerifiedBlockServer(processID);
      startServer(verifiedBlockServer);
      
      // This marks each block so that it's associated with the process that read in that blocks data
      SetBlockOwnership(blockDataList, processID, keyServer.getKeyPair());
      
      
      try {
         // Gives the individual servers time to start up before the process syncronize
         Thread.currentThread().sleep(1000);
      }
      catch(InterruptedException ie) {
         System.out.println(ie);
      }
      
      // Pause the processes until all three processes are running
      synchronizeProcesses();
      System.out.println("\nSystem now running\n");      
      
      
      // Send key and block data to all three processes
      keyServer.sendPublicKey();
      unverifiedBlockServer.sendStartingBlocks(blockDataList);
      
      
      try {
         // Gives the processes time to trade blocks.
         Thread.currentThread().sleep(1000);
      }
      catch(InterruptedException ie) {
         System.out.println(ie);
      }
      System.out.println("\nBlock sent, beginning work on solving unverified blocks.\n");
      Miner miner = new Miner(processID, keyServer, unverifiedBlockServer, verifiedBlockServer);
      miner.start();
      
      // The processes start working on assembling the block chain.
      boolean acceptingInput = true;
      while(acceptingInput) { 
         // The main thread has to wait for the miner to get done before displaying
         // the input prompt or the text of the prompt will get drowned out by the text from
         // the miner looking for solutions.
         while(miner.getState() != Thread.State.WAITING) {
            try {
               Thread.currentThread().sleep(500);
            }
            catch(InterruptedException ie) {
               System.out.println(ie);
            }
         }
         
         // There is a problem with doing it this way. All three processes will have the prompt for input displayed.
         // If one process selects to add a new file worth of data, the other two windows will begin filling up thier
         // displays with text about solving blocks. Only the main block though received input so that's the only block
         // that goes back to checking its miner. The others will still be waiting for input.
         // When the others are done, they won't dispaly the input prompt again because the have no way of knowing
         // that the input prompt isn't displaying. All three processes will still be able to accept input,
         // but they other two will no longe mention it unless some input is entered first, causing the prompt to reappear.
         Scanner userInput = new Scanner(System.in);
   
         System.out.println("\nType in one of the following commands");
         System.out.println("R [fileName] - Read in more data from the supplied file");
         System.out.println("C - Get the count of how many blocks each process has solved");
         System.out.println("L - List each block that is in the ledger");
         System.out.println("V - Verify the blockchain, checking that the winning hash is valid agains the previous hash");
         System.out.println("V threshold - Verify the block hash was under the guess threshold");
         System.out.println("V hash - Verify the block winning hash was signed");
         System.out.println("V signature - Verify the block ID was signed");
         
         // Wait for input from the console.
         String input = userInput.nextLine();
         if(input.equals("") || input == null) {
            continue;
         }
         String firstCharacter = input.substring(0, 1);
         
         if(firstCharacter.toLowerCase().equals("r")) {
            // There is a miner thread for each process that is waiting for new blocks to show up
            // in the concurrent queue. Once new blocks are added, they right away begin working
            // on trying to solve them. All this process needs to do is read in blocks, sign them
            // and the distribute them for the miners to start mining for answers.
            System.out.println("Looking for file");
            String fileName = input.substring(2);
            ArrayList<Block> readData = DataCollector.retrieveLedgerFromFile(fileName);
            SetBlockOwnership(readData, processID, keyServer.getKeyPair());
            unverifiedBlockServer.sendStartingBlocks(readData);
            
         }
         else if(firstCharacter.toLowerCase().equals("c")) {
            // This one just counts how many blocks each process has solved.
            int[] counts = new int[3];
            
            for(int i = 1; i < verifiedBlockServer.blockLedger.size(); i++) {
               Block block = verifiedBlockServer.blockLedger.get(i);
               int solvedID = Integer.parseInt(block.getVerifyingProcessID());
               counts[solvedID]++;
            }
            
            for(int i = 0; i < counts.length; i++) {
               System.out.println("Process " + i + " solved " + counts[i] + " blocks");
            }
         }
         else if(firstCharacter.toLowerCase().equals("l")) {
            // Blocks already have a toString method that prints out their data on
            // a line, so this is really just calling that method on each block in the ledger.
            for(int i = 1; i < verifiedBlockServer.blockLedger.size(); i++) {
               System.out.println(verifiedBlockServer.blockLedger.get(i));
            }
         }
         else if(firstCharacter.toLowerCase().equals("v")) {
            if(input.length() == 1) {
               verifyBlockChain("" , keyServer, verifiedBlockServer);
            }
            else {
               String verificationOption = input.substring(2);
               verifyBlockChain(verificationOption, keyServer, verifiedBlockServer);
            }
         

         }
      }
     
   }
   
   private static void verifyBlockChain(String option, KeyServer keyServer, VerifiedBlockServer vbServer) {
      ArrayList<Block> ledger = vbServer.blockLedger;
      if(option.trim().equals("")) {
         // Verify the blockchain, checking that the winning hash is valid agains the previous hash
         for(int i = 1; i < ledger.size(); i++) {
            Block block = ledger.get(i);
            Block previousBlock = ledger.get(i - 1);
            
            String guess = block.getRandomSeed() + block.getBlockNumber() + block.getVerifyingProcessID() + previousBlock.getWinningHash() + block.getFullData();
            
            byte[] guessHash = SecurityUtil.stringToSHAHash(guess);
            String hash = Arrays.toString(guessHash);
            if(!hash.equals(block.getWinningHash())) {
               if(i != 1) {
                  System.out.println("Blocks 1 - " + (i - 1) + " in the blockchain have been verified");
               }
               System.out.println("Block " + i + " invalid: winning hash wasn't valid");
               if( i != ledger.size() - 1) {
                  System.out.println("Blocks " + i + " - " +  (ledger.size() - 1) + " follow an invalid block");
               }
               return;
            }
         }
         System.out.println("All " + (ledger.size() - 1) + " blocks in the blockchain were verified");
      }
      
      else if(option.trim().equals("threshold")) {
         // Verify the block hash was under the guess threshold
         for(int i = 1; i < ledger.size(); i++) {
            Block block = ledger.get(i);
            // The stored guess has to be reconstructed into a byte array to hash it again
            byte[] winningHash = SecurityUtil.stringToByteArray(block.getWinningHash());
            int winningValue = Miner.twoBytesToInt(winningHash[0], winningHash[1]);
            
            if(winningValue >= Blockchain.guessThreshold) {
               if(i != 1) {
                  System.out.println("Blocks 1 - " + (i - 1) + " in the blockchain have been verified");
               }
               System.out.println("Block " + i + " invalid: SHA256 confirmed, but does not meet the work threshold");
               if( i != ledger.size() - 1) {
                  System.out.println("Blocks " + i + " - " +  (ledger.size() - 1) + " follow an invalid block");
               }
               return;
            }
         }
         System.out.println("All " + (ledger.size() - 1) + " blocks in the blockchain were verified");
      }
      
      else if(option.trim().equals("hash")) {
         // Verify the block winning hash was signed by the solving process
         for(int i = 1; i < ledger.size(); i++) {
            Block block = ledger.get(i);
            
            int verifyingProcess = Integer.parseInt(block.getVerifyingProcessID());
            PublicKey publicKey = keyServer.processPublicKeys.get(verifyingProcess);
            
            byte[] signedWinnigHash = SecurityUtil.stringToByteArray(block.getSignedWinningHash());
            byte[] winningHash = SecurityUtil.stringToByteArray(block.getWinningHash());
            boolean verified = false;
            try {
               verified = SecurityUtil.verifySig(winningHash, publicKey, signedWinnigHash);
            }
            catch(Exception e) {
               System.out.println(e);
            }     
            
            if(!verified) {
               if(i != 1) {
                  System.out.println("Blocks 1 - " + (i - 1) + " in the blockchain have been verified");
               }
               System.out.println("Block " + i + " invalid: the winning hash was not signed correctly");
               if( i != ledger.size() - 1) {
                  System.out.println("Blocks " + i + " - " +  (ledger.size() - 1) + " follow an invalid block");
               }
               return;
            }
         }
         System.out.println("All " + (ledger.size() - 1) + " blocks in the blockchain were verified");
      }
      
      else if(option.trim().equals("signature")) {
         // Verify the block ID and block data was signed by the process that created the block.
         for(int i = 1; i < ledger.size(); i++) {
            Block block = ledger.get(i);
            
            // There is already a function that checks this in the miner class, so it's just reused here.
            boolean verified = Miner.verifyBlockSignature(keyServer, block);            
            if(!verified) {
               if(i != 1) {
                  System.out.println("Blocks 1 - " + (i - 1) + " in the blockchain have been verified");
               }
               System.out.println("Block " + i + " invalid: the block ID was not signed correctly");
               if( i != ledger.size() - 1) {
                  System.out.println("Blocks " + i + " - " +  (ledger.size() - 1) + " follow an invalid block");
               }
               return;
            }
         }
         
         System.out.println("All " + (ledger.size() - 1) + " blocks in the blockchain were signature verified");
         
      }
   }
   
   
   
   private static void startServer(Server serverToStart) {
      Thread serverThread = new Thread(serverToStart);
      serverThread.start();
      activeThreads.add(serverThread);
   }
   
   private static void synchronizeProcesses() {
      // Causes the processes to wait until server 2 is started.
      if(processID != 2) {
         // Stop and wait if the current process isn't process 2.
         System.out.println("Waiting for process 2");
         try {   
            ServerSocket waitServer = new ServerSocket(Port.PROCESS_WAIT_BASE + processID, 6);
            waitServer.accept();
         }
         catch(IOException ioe) {
            System.out.println("Error while opening socket.");
            System.out.println(ioe);
         }
      }
      else {
         // This clause would happen if the calling process is proccess 2, and it should unblock the other two processes
         try {
            Socket unblockSocket = new Socket(serverName, Port.PROCESS_WAIT_BASE);
            unblockSocket = new Socket(serverName, Port.PROCESS_WAIT_BASE + 1);
         }
         catch(Exception e) {
            System.out.println("Error found while opening socket");
            System.out.println(e);
         }
      }
   }
   
   private static void SetBlockOwnership(List<Block> blockList, int processID, KeyPair keyPair) {
      for(int i = 0; i < blockList.size(); i++) {
         Block currentBlock = blockList.get(i);
         
         currentBlock.setOwningProcess(processID + "");
         
         String blockID = currentBlock.getBlockID();
         try {      
            // Sign the blockID
            byte[] signedID = SecurityUtil.signData(blockID.getBytes(), keyPair.getPrivate());
            currentBlock.setSignedBlockID(Arrays.toString(signedID));
         }
         catch(Exception e) {
            System.out.println(e);
         }
         
         // Consturct the concatination of the block data.
         String fullData = currentBlock.getOwningProcess() + currentBlock.getBlockID() + currentBlock.getTimeStamp() + currentBlock.getFirstName() + 
                           currentBlock.getLastName() + currentBlock.getSocialSecurityNumber() + currentBlock.getDateOfBirth() + currentBlock.getDiagnosis() +
                           currentBlock.getTreatment() + currentBlock.getPrescription();
         currentBlock.setFullData(fullData);
         try {
            // Hash the full block data
            byte[] hashedData = SecurityUtil.stringToSHAHash(fullData);
            // Sign the hash of the full block data
            byte[] signedHash = SecurityUtil.signData(hashedData, keyPair.getPrivate());
            currentBlock.setHashedAndSignedData(Arrays.toString(signedHash));
            
         }
         catch(Exception e) {
            System.out.println(e);
         }
      }
   }
   

}


class Miner extends Thread{
   int processID;
   KeyServer keyServer;
   UnverifiedBlockServer ubServer;
   VerifiedBlockServer vbServer;
   boolean running;
   
   public Miner (int processID, KeyServer keyServer, UnverifiedBlockServer ubServer, VerifiedBlockServer vbServer) {
      this.processID = processID;
      this.keyServer = keyServer;
      this.ubServer = ubServer;
      this.vbServer = vbServer;
   }

   public void run() {
      running = true;
      Block currentBlock = null;
      while(running) {
         try { 
            currentBlock = ubServer.unverifiedBlocks.take();
         }
         catch(Exception e) {
            System.out.println(e);
         }

         // Retrieve the previous block
         Block previousBlock = VerifiedBlockServer.blockLedger.get(VerifiedBlockServer.blockLedger.size() - 1);
         int previousBlockNumber = Integer.parseInt(previousBlock.getBlockNumber());


         previousBlockNumber++;
         int currentBlockNumber = previousBlockNumber;
         
         Blockchain.out.println("Working on block " + currentBlock.getBlockID());
         
         if(!verifyBlockSignature(keyServer, currentBlock)) {
            continue;
         }
         if(checkIfAlreadySolved(currentBlock)) {
            continue;
         }
         
         boolean foundSolution = false;
         Random rand = new Random();
         int checkCounter = 0;
         // The actual work that needs to be done
         while(!foundSolution) {
            try {
               // Wait a random amount between guesses.
               // This helps stagger the guesses in order to avoid race conditions where two processes
               // stumble upon a solution at the same time, and both attempt to update the ledger at the same time.
               Thread.currentThread().sleep((int)(Math.random() * 300) + 100);
            }
            catch(InterruptedException ie) {
               System.out.println(ie);
            }       
         
            if(checkIfAlreadySolved(currentBlock))
               break;
            
            // The random seed to be used as a guess
            String seed = rand.nextInt(Integer.MAX_VALUE) + "";
            // The full concatenated data that's going to be hashed
            String guess = seed + currentBlockNumber + processID + previousBlock.getWinningHash() + currentBlock.getFullData();
            
            byte[] guessHash = SecurityUtil.stringToSHAHash(guess);
            System.out.println("Guess Seed: " + seed);
            boolean guessValid = verifyGuessHash(guessHash);
                        
            if(guessValid) {
                  currentBlock.setBlockNumber(currentBlockNumber + "");
                  currentBlock.setVerifyingProcessID(processID + "");
                  currentBlock.setRandomSeed(seed);
                  currentBlock.setWinningHash(Arrays.toString(guessHash));
                  try {
                     // Sign the winning hash with the process's private key
                     byte[] signedWinningHash = SecurityUtil.signData(guessHash, keyServer.getKeyPair().getPrivate());
                     currentBlock.setSignedWinningHash(Arrays.toString(signedWinningHash));
                  }
                  catch(Exception e) {
                     System.out.println(e);
                  }
                  
                  
                  if(checkIfAlreadySolved(currentBlock)) {
                     // This block was solved before this process had a chance to report their solution
                     // The break statement should take the process out of the current guessing cycle
                     break;
                  }
                  else {
                     vbServer.blockVerified(currentBlock);
                     Blockchain.out.println("Found Block Solution\n");
                  }
            }
            checkCounter++;
         } 

      }
   }
   
   public static boolean verifyBlockSignature(KeyServer keyServer, Block block) {
      Integer processID = Integer.parseInt(block.getOwningProcess());
      PublicKey publicKey = KeyServer.processPublicKeys.get(processID);
      
      // The blockID was turned straight into bytes and then those bytes were signed so those are the bytes that need to be verified.
      byte[] signedBytes = SecurityUtil.stringToByteArray(block.getSignedBlockID());     
      try {
         boolean blockIDVerified = SecurityUtil.verifySig(block.getBlockID().getBytes(), publicKey, signedBytes);
         if(!blockIDVerified)
            return false;
         Blockchain.out.println("Block " + block.getBlockID() + " blockID signature verified");
      }
      catch(Exception e) {
         System.out.println(e);
      }
      
      // The fullData was hashed and then signed. To verify, the full data needs to be hashed and then verified
      try {
         // Hash the full block data
         byte[] hashedData = SecurityUtil.stringToSHAHash(block.getFullData());
         // Recover the byte array from the string store in the block
         byte[] hashedAndSignedData = SecurityUtil.stringToByteArray(block.getHashedAndSignedData());
         boolean blockDataVerified = SecurityUtil.verifySig(hashedData, publicKey, hashedAndSignedData);
         if(!blockDataVerified)
            return false;
         Blockchain.out.println("Block " + block.getBlockID() + " blockData signature verified");
      }
      catch(Exception e) {
         System.out.println(e);
      }
      
      return true;
   }
   
   public static boolean checkIfAlreadySolved(Block block) {
      // Compare the blockIDs of each block in the ledger against the passed in block to see if any of them match.
      ArrayList<Block> ledger = VerifiedBlockServer.blockLedger;
      for(int i = 0; i < ledger.size(); i++) {
         Block ledgerBlock = ledger.get(i);
         if(block.getBlockID().equals(ledgerBlock.getBlockID())) {
            System.out.println("Duplicate found\n");
            return true;
         }
      }
      return false;
   }
   
   public static boolean verifyGuessHash(byte[] guess) {
      
      int leftSixteenBitsValue = twoBytesToInt(guess[0], guess[1]); 
      
      return leftSixteenBitsValue < Blockchain.guessThreshold;
   }
   
   public static int twoBytesToInt(byte x, byte y) {
      int result = 0;
      
      // Take the bits from byte x
      for(int i = 7; i >= 0; i--) {
         // Shift the bits in result to the left 1.
         result *= 2;
         // Retrive the unexamined bit furthest to the left in the byte.
         int shiftedX = x >> i;
         // After this &, bit will contain a 1 or 0, depending on the first bit in shiftedX.
         int bit = shiftedX & 1;
         result += bit;
      }
      // Take the bits from byte y
      for(int i = 7; i >= 0; i--) {
         // Shift the bits in result to the left.
         result *= 2;
         // Retrive the unexamined bit furthest to the left in the byte.
         int shiftedY = y >> i;
         // After this &, bit will contain a 1 or 0, depending on the first bit in shiftedX.
         int bit = shiftedY & 1;
         result += bit;
      }
      
      
      return result;
   }
   
   public static boolean numberAlreadyInUse(int desiredNumber) {
      ArrayList<Block> ledger = VerifiedBlockServer.blockLedger;
      for(int i = 0; i < ledger.size(); i++) {
         int blockNumber = Integer.parseInt(ledger.get(0).getBlockNumber());
         if(blockNumber == desiredNumber)
            return true;
      }
      return false;
   }
}


/* --------------------------- Start of Servers ------------------------ */

abstract class Server implements Runnable {
   public int processID;
   
   public Server(int processID) {
      this.processID = processID;
   }
}



/* ---------------------------- Key Server ------------------------------*/

class KeyServer extends Server{
   private KeyPair keyPair;
   public KeyPair getKeyPair() {
      return keyPair;
   }
   
   public boolean running;
   
   // Maps process IDs to their public key
   public static ConcurrentHashMap<Integer, PublicKey> processPublicKeys;
   /*
      To turn private / public keys into strings
         
         Arrays.toString(keyPair.getPrivate().getEncoded())
         
      This turns it into a byte array and then into a string. It then needs to be reconstructed at the receiving end back into a key to be used.
   */
     
   public KeyServer(int processID) {
      super(processID);
      // Maps the processIDs to their public keys.
      processPublicKeys = new ConcurrentHashMap<Integer, PublicKey>();
      try {
         keyPair = SecurityUtil.generateKeyPair(new Random().nextLong());
      }
      catch(Exception ex) {
         Blockchain.out.println("Exception found while generating key pair.");
         Blockchain.out.println(ex);
      }
   }
   
   @Override
   public void run() {
      running = true;
      Blockchain.out.println("Starting Key Server");
      Socket socket;
      
      try {
         ServerSocket serverSocket = new ServerSocket(Port.PUBLIC_KEY_BASE + processID, 6);
         while(running) {
            // Pauses while waiting for a soccect to connect on the other end.
            socket = serverSocket.accept();
            new KeyServerWorker(socket).start();
         }
         
      }
      catch(Exception e) {
         System.out.println("Unable to start key server ServerSocket");
         System.out.println(e);
      }
   }
   
   public void sendPublicKey() {
      // The sockets are hardcoded to just send to three receivers.
      // Using a list and a global count, it might be possibe to send keys to
      // an arbitrary amount of other processes.
      
      // Turns the process public key into a byte array.
      byte[] publicEncodedKey = keyPair.getPublic().getEncoded();
      for(int i = 0; i <= 2; i++) {
         try {
            Socket socket = new Socket(Blockchain.serverName, Port.PUBLIC_KEY_BASE + i);
            DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
            outputStream.writeInt(processID);
            outputStream.writeInt(publicEncodedKey.length);
            outputStream.write(publicEncodedKey);           
         }
         catch(IOException ioe) {
            System.out.println(ioe);
         }

      }
   }
}

class KeyServerWorker extends Thread {
   Socket socket;
   public KeyServerWorker(Socket socket) {
      this.socket = socket;
   }
   @Override
   public void run() {
      int readProcessID = -1;
      byte[] publicByteKey = new byte[0];
      
      try {
         // Read in the public key. First, the length of the public key in bytes in needed.
         DataInputStream inputStream = new DataInputStream(socket.getInputStream());
         readProcessID = inputStream.readInt();
         int keyByteLength = inputStream.readInt();
         publicByteKey = new byte[keyByteLength];
         inputStream.readFully(publicByteKey, 0, keyByteLength);
      }
      catch(IOException ioe) {
         System.out.println(ioe);
      }
      try {
         // Recreate the public key from the read in data.
         PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicByteKey));
         if(!KeyServer.processPublicKeys.containsKey(readProcessID)) {   
            KeyServer.processPublicKeys.put(readProcessID, publicKey);
            Blockchain.out.println("Adding public key for " + readProcessID);
         }
         
      }
      catch(Exception e) {
         System.out.println(e);
      }


   }
}



/* --------------------- Unverified Block Server ----------------------- */

class  UnverifiedBlockServer extends Server {
   public static PriorityBlockingQueue<Block> unverifiedBlocks;

   public boolean running;
   
   public UnverifiedBlockServer(int processID) {
      super(processID);
      // A capacity of 12 is supplied to the priority queue because there are 3 processes each reading in 4 records.
      // It doesn't seem like the initial capacity matters though for a priority blocking queue since the java docs
      // are saying that the queue isn't capacity bounded. There wasn't a constructor though that took only a comparator
      // so this one had to be used instead.
      unverifiedBlocks = new PriorityBlockingQueue<Block>(12, new BlockComparator());
   }
   
   @Override
   public void run() {
      running = true;
      Blockchain.out.println("Starting Unverified Block Server");
      Socket socket;
      
      try {
         ServerSocket serverSocket = new ServerSocket(Port.UNVERIFIED_BLOCK_BASE + processID, 6);
         while(running) {
            // Pauses while waiting for a soccect to connect on the other end.
            socket = serverSocket.accept();
            new UnverifiedBlockWorker(socket).start();
         }
         
      }
      catch(Exception e) {
         System.out.println("Unable to start unverified block server ServerSocket");
         System.out.println(e);
      }
   }
   
   
   public void sendStartingBlocks(List<Block> blockList) {
      for(int i = 0; i < blockList.size(); i++) {
         // Create the JSON string from each block
         Gson gson = new Gson();
         String json = gson.toJson(blockList.get(i));
         
         // Send the JSON string to the three different processes
         for(int j = 0; j <= 2; j++) {
            try {
               Socket socket = new Socket(Blockchain.serverName, Port.UNVERIFIED_BLOCK_BASE + j);
               PrintStream outputStream = new PrintStream(socket.getOutputStream());
               outputStream.println(json);
               System.out.println("Sending block " + blockList.get(i).getBlockID() + " to process " + j);
            }
            catch(Exception e) {
               System.out.println(e);
            }
         }
      }
   }
}

class UnverifiedBlockWorker extends Thread{
   Socket socket;
   
   public UnverifiedBlockWorker(Socket socket) {
      this.socket = socket;
   }
   
   @Override
   public void run() {
      // This should do something when the UnverifiedBlockServer is connected to. 
      // A block has been sent by some other process, and it's up to this worker to
      // handle adding it to the priority blocking queue.
      try {
         BufferedReader inputStream = new BufferedReader(new InputStreamReader(socket.getInputStream()));
         // Read the unformated JSON
         String incomingJSON = inputStream.readLine();
         Gson gson = new Gson();
         // Convert the JSON string into a block
         Block jsonBlock = gson.fromJson(incomingJSON, Block.class);
         UnverifiedBlockServer.unverifiedBlocks.add(jsonBlock);
      }
      catch(IOException ioe) {
         System.out.println(ioe);
      }

   }
   
}


/* ----------------------- Verified Block Server  ---------------------------- */

class  VerifiedBlockServer extends Server {

   public boolean running;
   public static ArrayList<Block> blockLedger;
   
   public VerifiedBlockServer(int processID) {
      super(processID);
      blockLedger = new ArrayList<Block>();
      
      
      // Add a dummy block to the front of the ledger to be used as a jumping off point for future work done by processes.
      // When a new block is being verified, the verifying process uses the previous verified block's number and its
      // winning hash, so these are the only values that are loaded into the dummyBlock.
      Block dummyBlock = new Block();
      dummyBlock.setBlockNumber("0");
      dummyBlock.setFullData("This is just test data.");
      try {
         byte[] dummyHash = SecurityUtil.stringToSHAHash(dummyBlock.getFullData());
         dummyBlock.setWinningHash(Arrays.toString(dummyHash));
      }
      catch(Exception e) {
         System.out.println(e);
      }
      blockLedger.add(dummyBlock);
   }
   
   @Override
   public void run() {
      running = true;
      Blockchain.out.println("Starting Verified Block Server");
      Socket socket;
      
      try {
         ServerSocket serverSocket = new ServerSocket(Port.VERIFIED_BLOCK_BASE + processID, 6);
         while(running) {
            // Pauses while waiting for a soccect to connect on the other end.
            socket = serverSocket.accept();
            new VerifiedBlockWorker(socket, processID).start();
         }
         
      }
      catch(Exception e) {
         System.out.println("Unable to start verified block server ServerSocket");
         System.out.println(e);
      }
   }
   
   public void blockVerified(Block block) {
      blockLedger.add(block);
      broadcastLedger();
   }
   
   public void broadcastLedger() {
      // Once a new block is added, the process that sovled the block needs to broadcast out the new ledger.
      Gson gson = new Gson();
      for(int i = 0; i <= 2; i++) {
         try {
            Blockchain.out.println("Sending ledger to process " + i);
            Socket socket = new Socket(Blockchain.serverName, Port.VERIFIED_BLOCK_BASE + i);
            PrintStream outputStream = new PrintStream(socket.getOutputStream());
            // Send the other process the size of the new ledger so that it knows how many blocks to expect.
            outputStream.println(blockLedger.size());
            for(int j = 0; j < blockLedger.size(); j++) {
               // Send each block to the current process being talked to.
               String jsonBlock = gson.toJson(blockLedger.get(j));
               outputStream.println(jsonBlock);
            }
         }
         catch(Exception e) {
            System.out.println(e);
         }
      }
   }

}

class VerifiedBlockWorker extends Thread{
   private Socket socket;
   private int processID; 
   public VerifiedBlockWorker(Socket socket, int processID) {
      this.socket = socket;
      this.processID = processID;
   }
   
   @Override
   public void run() {
      // This runs when the server is connected to, and the process at the other end is broadcasting a ledger.
      try {
         Gson gson = new Gson();
         BufferedReader inputStream = new BufferedReader(new InputStreamReader(socket.getInputStream()));
         String countString = inputStream.readLine();
         // Read in how many blocks are in the new ledger
         int count = Integer.parseInt(countString);
         ArrayList<Block> receivedList = new ArrayList<Block>();
         for(int i = 0; i < count; i++) {
            String jsonBlock = inputStream.readLine();
            Block receivedBlock = gson.fromJson(jsonBlock, Block.class);
            // This saves the new ledger in a temporary array list and the new list in for the old.
            // This makes it so that the ledger isn't changing one by one as each block is received,
            // which could introduce race conditions on what part of the process is accessing the ledger.
            receivedList.add(receivedBlock);
         }
         VerifiedBlockServer.blockLedger = receivedList;
         Blockchain.out.println("Received new ledger");
         if(processID == 0) {
            writeLedgerToFile(receivedList.get(receivedList.size() - 1));
         }
      }
      catch(Exception e) {
         System.out.println(e);
      }
   }
   
   public static void writeLedgerToFile(Block block) {    
      Gson gson = new GsonBuilder().setPrettyPrinting().create();           
      try (FileWriter writer = new FileWriter("BlockchainLedger.json", true)) {
         // This appends the new block to be written to the end of the current ledger file.
         gson.toJson(block, writer);
         writer.write(System.lineSeparator());
      } 
      catch (IOException e) {
         e.printStackTrace();
      }
   }
   
}


/* ------------------- End of Servers ------------------------------- */



// The class for reading data from the supplied files.
// It will also turn the data into a queue that can then be used by the calling process.
class DataCollector {

   public static ArrayList<Block> retrieveLedgerFromFile(String fileName) {
   
      ArrayList<Block> foundBlocks = new ArrayList<Block>();
      
      ArrayList<String> fileContents = retrieveFileContents(fileName);
      for(int i = 0; i < fileContents.size(); i++) {
         String fullData = fileContents.get(i);
         // System.out.println("Current Row of Data: " + fullData);
         
         
         // The different values in the input text files are seperated by a space 
         String[] splitData = splitDataRow(fullData);
         Block block = new Block();
         
         // Creating a new date will set the date's time the date object is created.
         DateTimeFormatter dtf = DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm:ss.SS");
         LocalDateTime now = LocalDateTime.now();  
         
         block.setTimeStamp(dtf.format(now));
         
         // Take the rest of the data from the file
         block.setFirstName(splitData[0]);
         block.setLastName(splitData[1]);
         block.setDateOfBirth(splitData[2]);
         block.setSocialSecurityNumber(splitData[3]);
         block.setDiagnosis(splitData[4]);
         block.setTreatment(splitData[5]);
         block.setPrescription(splitData[6]);
         
         // Assign the block a random UUID
         block.setBlockID(UUID.randomUUID().toString());
         
         foundBlocks.add(block);
         
         // Pauses slightly so that different blocks have diffent time codes.10
         // Without this, the time stamps on a lot of the blocks is very similar 
         try {
            
            Thread.currentThread().sleep(50);
         }
         catch(InterruptedException e) {
            System.out.println(e);
         }
      } 
      return foundBlocks;
   }
   
   public static ArrayList<String> retrieveFileContents(String fileName) {
      ArrayList<String> contents = new ArrayList<String>();
      
      File file;
      Scanner fileScan;
      try {
      
         file = new File(fileName);
         fileScan = new Scanner(file);
      }
      catch(FileNotFoundException fnfException) {
         System.out.println("File " + fileName + " could not be found");
         return null;
      }
      
      // Read in each line of the file, one line at a time, until the scanner reaches the end of the file.
      while(fileScan.hasNextLine()) {
         contents.add(fileScan.nextLine());
      }
      fileScan.close();
      return contents;
   }
   
   public static String[] splitDataRow(String data) {
      // The values in the data string are seperated by spaces.
      // Sometimes there are multiple spaces between each value, so simply calling data.Split() wouldn't work.
      // This is a solution for extracting the individual values while ignoring the spaces.
      
      String[] splitData = new String[7];
      for(int i = 0; i < splitData.length; i++) {     
         data = data.trim();
         int spaceIndex = data.indexOf(" ");
         if(spaceIndex == -1)
            spaceIndex = data.length();
         
         splitData[i] = data.substring(0, spaceIndex);
         data = data.substring(spaceIndex);
      }
      
      return splitData;
   }
}

class Block implements Serializable{
   // This is the processID of the process that read in the block
   private String owningProcess;
   public String getOwningProcess() {
      return owningProcess;
   }
   public void setOwningProcess(String owningProcess) {
      this.owningProcess = owningProcess;
   }
   // This is the processID of the process that verified the block
   private String verifyingProcessID;
   public String getVerifyingProcessID() {
      return verifyingProcessID;
   }
   public void setVerifyingProcessID(String verifyingProcessID) {
      this.verifyingProcessID = verifyingProcessID;
   }
   // A sequential block number
   private String blockNumber;
   public String getBlockNumber() {
      return blockNumber;
   }
   public void setBlockNumber(String blockNumber) {
      this.blockNumber = blockNumber;
   }
   // A randomly generated UUID
   private String blockID;
   public String getBlockID() {
      return blockID;
   }
   public void setBlockID(String blockID) {
      this.blockID = blockID;
   }
   // The time the block was created
   private String timeStamp;
   public String getTimeStamp() {
      return timeStamp;
   }
   public void setTimeStamp(String timeStamp) {
      this.timeStamp = timeStamp;
   }
   // The next several fields are each just data that was read in from a file
   private String firstName;
   public String getFirstName() {
      return firstName;
   }
   public void setFirstName(String firstName) {
      this.firstName = firstName;
   }
   
   private String lastName;
   public String getLastName() {
      return lastName;
   }
   public void setLastName(String lastName) {
      this.lastName = lastName;
   }
   
   private String socialSecurityNumber;
   public String getSocialSecurityNumber() {
      return socialSecurityNumber;
   }
   public void setSocialSecurityNumber(String socialSecurityNumber) {
      this.socialSecurityNumber = socialSecurityNumber;
   }
   
   private String dateOfBirth;
   public String getDateOfBirth() {
      return dateOfBirth;
   }
   public void setDateOfBirth(String dateOfBirth) {
      this.dateOfBirth = dateOfBirth;
   }
   
   private String diagnosis;
   public String getDiagnosis() {
      return diagnosis;
   }
   public void setDiagnosis(String diagnosis) {
      this.diagnosis = diagnosis;
   }
   
   private String treatment;
   public String getTreatment() {
      return treatment;
   }
   public void setTreatment(String treatment) {
      this.treatment = treatment;
   }
   
   private String prescription;
   public String getPrescription() {
      return prescription;
   }
   public void setPrescription(String prescription) {
      this.prescription = prescription;
   }   
   // The seed that was the winning guess for the block
   private String randomSeed;
   public String getRandomSeed() {
      return randomSeed;
   }
   public void setRandomSeed(String randomSeed) {
      this.randomSeed = randomSeed;
   }
   // The hash that resulted in solving the puzzle
   private String winningHash;
   public String getWinningHash() {
      return winningHash;
   }
   public void setWinningHash(String winningHash) {
      this.winningHash = winningHash;
   }
   // The winning hash signed with the private key of the process that solved it
   private String signedWinningHash;
   public String getSignedWinningHash() {
      return signedWinningHash;
   }
   public void setSignedWinningHash(String signedWinningHash) {
      this.signedWinningHash = signedWinningHash;
   }
   // Different pieces of block data that are concatenated together
   private String fullData;
   public String getFullData() {
      return fullData;
   }   
   public void setFullData(String fullData) {
      this.fullData = fullData;
   }
   // The block ID signed with a processes private key
   private String signedBlockID;
   public String getSignedBlockID() {
      return signedBlockID;
   }
   public void setSignedBlockID(String signedBlockID) {
      this.signedBlockID = signedBlockID;
   }
   // The hash of full data that has been signed with the processes private key
   private String hashedAndSignedData;
   public String getHashedAndSignedData() {
      return hashedAndSignedData;
   }
   public void setHashedAndSignedData(String hashedAndSignedData) {
      this.hashedAndSignedData = hashedAndSignedData;
   }
   

   
   @Override
   public String toString() {
      String stringForm = "";
      stringForm += blockNumber + " " + timeStamp + " " + firstName + "  " + lastName + " " + socialSecurityNumber + " " + dateOfBirth + " " + diagnosis + " " + treatment + " " + prescription + " " + blockID;
      return stringForm;
   }
}


// Compares blocks based on their stored timestamp
class BlockComparator implements Comparator<Block> {

   @Override
   public int compare(Block x, Block y) {     
      if(x == null && y == null) {
         return 0;
      }  
      else if(x == null) {
         return -1;
      }
      else if(y == null) {
         return 1;
      }
      // Setup a date format that's consistent with the local settings.
      // The date format also matches the format of what's being stored in each block.
      DateFormat format = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss.SS", Locale.ENGLISH);
      Date xDate;
      Date yDate;
      
      
      try {
         xDate = format.parse(x.getTimeStamp());
      }
      catch(ParseException pe) {
         System.out.println("Unable to parse time for block" + x.getBlockID());
         return -1;
      }
      
      try {
         yDate = format.parse(y.getTimeStamp());
      }
      catch(ParseException pe) {
         System.out.println("Unable to parse time for " + y.getBlockID());
         return 1;
      }
      // If the timestamps are the same, then the processID is used as a tie breaker.
      if(xDate.compareTo(yDate) != 0) {   
         return xDate.compareTo(yDate);
      }
      else {
         Integer xID = Integer.parseInt(x.getOwningProcess());
         Integer yID = Integer.parseInt(y.getOwningProcess());
      
         return xID.compareTo(yID);
      }
      
   }      

}

// This class is used for signing and verifying signatures.
// It also deals with some byte manipulation as well.
// Most of the methods were taken from the BlockJ.java file.
class SecurityUtil {

   public static void signBlocks() {
      
   }

   public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
      Signature signer = Signature.getInstance("SHA1withRSA");
      signer.initVerify(key);
      signer.update(data);
    
      return (signer.verify(sig));
   }
  
   public static KeyPair generateKeyPair(long seed) throws Exception {
      KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
      SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
      rng.setSeed(seed);
      keyGenerator.initialize(1024, rng);
    
      return (keyGenerator.generateKeyPair());
   }
  
   public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
      Signature signer = Signature.getInstance("SHA1withRSA");
      signer.initSign(key);
      signer.update(data);
      return (signer.sign());
   }
   
   public static byte[] stringToSHAHash(String data) {
      MessageDigest md = null;
      try {
         md = MessageDigest.getInstance("SHA-256");
         md.update (data.getBytes());
      }
      catch(NoSuchAlgorithmException e) {
         System.out.println(e);
      }
      return md.digest();
   }

   public static byte[] stringToByteArray(String data) {
      // Byte arrays turned into strings using Arrays.toString() end up
      // having the values be comma seperated and surrounded by brackets.
      // This will convert a string in the form of [n1, n2, n3] back into a byte array
      
      // This removes the square brackets surrounding the values
      data = data.substring(1);
      data = data.substring(0, data.length() - 1);
      // Split string into a string array so that each index of the array holds a byte in string form.
      String[] splitData = data.split(", ");
      byte[] byteData = new byte[splitData.length];   
      for(int i = 0; i < splitData.length; i++) {
         // Parse the string back into a byte.
         byteData[i] = Byte.parseByte(splitData[i]);
      }
      
      return byteData;
   }
}

class Port {
   // Just the base ports used throughout the program.
   public static final int PUBLIC_KEY_BASE = 4710;
   public static final int UNVERIFIED_BLOCK_BASE = 4820;
   public static final int VERIFIED_BLOCK_BASE = 4930;
   public static final int PROCESS_WAIT_BASE = 5100;

}