import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";
import { BASE_USER_PORT } from "../config";
import { REGISTRY_PORT } from "../config";
import { Node } from "../registry/registry";
import { rsaEncrypt, createRandomSymmetricKey, exportSymKey, symEncrypt } from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: Node[] = [];

  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // 1.2 implement the status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // 2.2 user's GET routes
  // /getLastReceivedMessage
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });
  // /getLastSentMessage
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  // 4 sending messages to users
  // /message
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  // 6.1 users' /sendMessage route
  // /sendMessage
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;
    let circuit: Node[] = [];

    // create a random circuit of 3 distinct nodes with the help of the node registry
    // get the node registry
    const nodes = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`)
      .then((res) => res.json())
      .then((body: any) => body.nodes);

    // pick 3 random different nodes
    while (circuit.length < 3) {
      const randomIndex = Math.floor(Math.random() * nodes.length);
      if (!circuit.includes(nodes[randomIndex])) {
        circuit.push(nodes[randomIndex]);
      }
    }

    lastSentMessage = message;
    let messageToSend = lastSentMessage;
    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
    // create each layer of encryption for each node in the circuit
    for (let i = 0; i < circuit.length; i++) {
      const node = circuit[i];
      // create a symmetric key for each node in the circuit
      const symKey = await createRandomSymmetricKey();
      // (1) the previous value and the message should be concatenated and encrypted with the associated symmetricKey
      const messageToEncrypt = `${destination + messageToSend}`;
      // encode the destinationUserId as a 10 character string
      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, "0");
      const encryptedMessage = await symEncrypt(symKey, messageToEncrypt);
      // (2) then the symmetricKey needs to be encrypted with the associated node's pubKey
      const encryptedSymKey = await rsaEncrypt(await exportSymKey(symKey), node.pubKey);
      // then (2) should be concatenated with (1) in this order
      messageToSend = encryptedSymKey + encryptedMessage;
    }

    // reverse the circuit
    circuit.reverse();

    // forward the encrypted message to the entry node
    const entryNode = circuit[0];
    lastCircuit = circuit;
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + entryNode.nodeId}/message`, {
      method: "POST",
      body: JSON.stringify({ message: messageToSend }),
      headers: {
        "Content-Type": "application/json",
      },
    });

    res.send("success");
  });

  // /getLastCircuit
  _user.get("/getLastCircuit", (req, res) => {
    // return only the nodeId of each node in the circuit
    res.json({ result: lastCircuit.map((node) => node.nodeId) });
  });

  return server;
}
