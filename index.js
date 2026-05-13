const path = require("path");
const { spawn } = require("child_process");
const serverless = require("serverless-http");
require("express");
const app = require("./proxy");

const isServerless = !!(
    process.env.VERCEL ||
    process.env.VERCEL_ENV ||
    process.env.AWS_EXECUTION_ENV ||
    process.env.LAMBDA_TASK_ROOT
);

if (isServerless) {
    module.exports.handler = serverless(app);
} else {
    const SCRIPT_FILE = "proxy.js";
    const SCRIPT_PATH = path.join(__dirname, SCRIPT_FILE);

    console.log("SCRIPT_PATH:", SCRIPT_PATH);

    const restartEnabled = process.env.PID !== "0";

    let mainProcess;

    function start() {
        console.log("Starting main process...");

        mainProcess = spawn("node", ["--no-deprecation", "--no-warnings", SCRIPT_PATH], {
            cwd: __dirname,
            stdio: "inherit",
            shell: true,
        });

        mainProcess.on("error", (err) => {
            console.error("Error occurred while starting the process:", err);
        });

        mainProcess.on("close", (exitCode) => {
            console.log(`Process exited with code [${exitCode}]`);
            if (restartEnabled) {
                console.log("Restarting process...");
                restartProcess();
            } else {
                console.log("Shutdown initiated...");
                process.exit(exitCode);
            }
        });
    }

    function restartProcess() {
        if (mainProcess && mainProcess.pid) {
            mainProcess.kill("SIGKILL");
            console.log("Main process killed. Restarting...");
        }
        start();
    }

    start();
}
