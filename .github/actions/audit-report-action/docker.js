import { Config } from "./config";

const child_process = require('child_process');

export async function buildImage(imageName, path) {
  child_process.spawnSync("docker", ["build", "-t", imageName, path], {
    encoding: 'utf-8',
    maxBuffer: Config.spawnProcessBufferSize
  });
}

export async function cleanupImage(imageName) {
  child_process.spawnSync("docker", ["rmi", imageName], {
    encoding: 'utf-8',
    maxBuffer: Config.spawnProcessBufferSize
  });
}

export async function pullImage(imageName) {
  child_process.spawnSync("docker", ["pull", `trubudget/${imageName}`], {
    encoding: 'utf-8',
    maxBuffer: Config.spawnProcessBufferSize
  });
  child_process.spawnSync("docker", ["save", `trubudget/${imageName}`, "-o", `${imageName}.tar`], {
    encoding: 'utf-8',
    maxBuffer: Config.spawnProcessBufferSize
  });
}