import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  let getNodeRegistryBody: GetNodeRegistryBody = { nodes: [] };

  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // 1.3 implement the status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // 3.1 allow nodes to register themselves
  // /registerNode
  _registry.post("/registerNode", (req: Request<RegisterNodeBody>, res: Response) => {
    const { nodeId, pubKey } = req.body;
    getNodeRegistryBody.nodes.push({ nodeId, pubKey });
    res.json({ result: "success" });
  });

  // 3.4 allow users to retrieve the registry
  // /getNodeRegistry
  _registry.get("/getNodeRegistry", (req, res) => {
    res.json(getNodeRegistryBody);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
