import React, { useState } from "react";
import axios from "axios";

const Node_A = () => {
  const [response, setResponse] = useState("");
  const baseURL = "http://127.0.0.1:8002"; // Replace with your FastAPI server's base URL
  const config = {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,PATCH,OPTIONS"
    }
  };

  const handleButtonClick = async (endpoint) => {
    try {
      
      const res = await axios.get(`${baseURL}${endpoint}`);
      console.log("data-> ", res.data);
      
      setResponse(JSON.stringify(res.data, null, 2));
      
    } catch (error) {
      console.error("Error:", error);
      setResponse(`Error: ${error.response?.data || error.message}`);
    }
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      <h1>Node API Interface</h1>
      <div style={{ marginBottom: "20px" }}>
        <button
          onClick={() => handleButtonClick("/serverinfo")}
          style={buttonStyle}
        >
          Fetch Server Info
        </button>
        <button
          onClick={() => handleButtonClick("/generatekeys")}
          style={buttonStyle}
        >
          Generate Keys
        </button>
        <button
          onClick={() => handleButtonClick("/send_public_key")}
          style={buttonStyle}
        >
          Generate partial public keys
        </button>
        {/* <button
          onClick={() => handleButtonClick("/receive_public_key")}
          style={buttonStyle}
        >
          receive public key
        </button> */}
        <button
          onClick={() => handleButtonClick("/authenticate")}
          style={buttonStyle}
        >
          Authenticate
        </button>
        <button
          onClick={() => handleButtonClick("/GenerateSessionKey")}
          style={buttonStyle}
        >
          Generate Session Key
        </button>
      </div>
      <h2>Response:</h2>
      <pre style={responseStyle}>{response}</pre>
    </div>
  );
};

const buttonStyle = {
  margin: "10px",
  padding: "10px 20px",
  backgroundColor: "#007BFF",
  color: "#FFFFFF",
  border: "none",
  borderRadius: "5px",
  cursor: "pointer",
  fontSize: "16px",
};

const responseStyle = {
  color:"black",
  padding: "10px",
  backgroundColor: "#F5F5F5",
  border: "1px solid #DDD",
  borderRadius: "5px",
  maxHeight: "300px",
  overflowY: "scroll",
  whiteSpace: "pre-wrap",
  wordWrap: "break-word",
};

export default Node_A;
