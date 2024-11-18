// import React, { useState } from "react";
// import axios from "axios";

// const Node_A = () => {
//   const [response, setResponse] = useState("");
//   // const [msg, setmsg] = useState(false);
//   const [session, setsession] = useState(false);

//   const baseURL = "http://127.0.0.1:8001"; // Replace with your FastAPI server's base URL
//   const config = {
//     headers: {
//       "Access-Control-Allow-Origin": "*",
//       "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,PATCH,OPTIONS"
//     }
//   };

//   const handleButtonClick = async (endpoint) => {
//     try {
//       const res = await axios.get(`${baseURL}${endpoint}`);
//       if(endpoint=="/GenerateSessionKey"){
//         setsession(true);
//       }
//       console.log("data-> ", res.data);
      
//       setResponse(JSON.stringify(res.data, null, 2));
      
//     } catch (error) {
//       console.error("Error:", error);
//       setResponse(`Error: ${error.response?.data || error.message}`);
//     }
//   };

//   return (
//     <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
//       <h1>Node API Interface</h1>
//       <div style={{ marginBottom: "20px" }}>
//         <button
//           onClick={() => handleButtonClick("/serverinfo")}
//           style={buttonStyle}
//         >
//           Fetch Server Info
//         </button>
//         <button
//           onClick={() => handleButtonClick("/generatekeys")}
//           style={buttonStyle}
//         >
//           Generate Keys
//         </button>
//         <button
//           onClick={() => handleButtonClick("/send_public_key")}
//           style={buttonStyle}
//         >
//           Generate partial public keys
//         </button>
//         {/* <button
//           onClick={() => handleButtonClick("/receive_public_key")}
//           style={buttonStyle}
//         >
//           receive public key
//         </button> */}
//         <button
//           onClick={() => handleButtonClick("/authenticate")}
//           style={buttonStyle}
//         >
//           Authenticate
//         </button>
//         <button
//           onClick={() => handleButtonClick("/GenerateSessionKey")}
//           style={buttonStyle}
//         >
//           Generate Session Key
//         </button>
//         <button
//           onClick={() => handleButtonClick("/Message")}
//           style={buttonStyle}
//         >
//           Check message
//         </button>
//       </div>
//       <h2>Response:</h2>
//       <pre style={responseStyle}>{response}</pre>
//       {session && 
//       <div>
//       <form action={`${baseURL}/Encryption`} method ="POST">
//         <textarea name="message" id=""></textarea>
//         <button type="submit">Submit</button>
//         </form>  
//       </div>}
//     </div>
//   );
// };

// const buttonStyle = {
//   margin: "10px",
//   padding: "10px 20px",
//   backgroundColor: "#007BFF",
//   color: "#FFFFFF",
//   border: "none",
//   borderRadius: "5px",
//   cursor: "pointer",
//   fontSize: "16px",
// };

// const responseStyle = {
//   color:"black",
//   padding: "10px",
//   backgroundColor: "#F5F5F5",
//   border: "1px solid #DDD",
//   borderRadius: "5px",
//   maxHeight: "300px",
//   overflowY: "scroll",
//   whiteSpace: "pre-wrap",
//   wordWrap: "break-word",
// };

// export default Node_A;



import React, { useState } from "react";
import axios from "axios";

const Node_A = () => {
  const [response, setResponse] = useState("");
  const [session, setSession] = useState(false);
  const [message, setMessage] = useState("");
  const [newMessage, setNewMessage] = useState("");

  const baseURL = "http://127.0.0.1:8002"; // Replace with your FastAPI server's base URL

  const handleButtonClick = async (endpoint) => {
    try {
      const res = await axios.get(`${baseURL}${endpoint}`);
      if (endpoint === "/GenerateSessionKey") {
        setSession(true);
      }
      console.log("data-> ", res.data);
      setResponse(JSON.stringify(res.data, null, 2));
    } catch (error) {
      console.error("Error:", error);
      setResponse(`Error: ${error.response?.data || error.message}`);
    }
  };

  const handleSendMessage = async () => {
    try {
      const res = await axios.post(`${baseURL}/Encryption`, { message });
      setResponse(`Message sent: ${JSON.stringify(res.data, null, 2)}`);
      setMessage(""); // Clear the message after sending
    } catch (error) {
      console.error("Error:", error);
      setResponse(`Error: ${error.response?.data || error.message}`);
    }
  };

  const handleCheckMessage = async () => {
    try {
      const res = await axios.get(`${baseURL}/Message`);
      setNewMessage(res.data.DecryptedMessage || "No new messages.");
      setResponse(`New message: ${JSON.stringify(res.data, null, 2)}`);
    } catch (error) {
      console.error("Error:", error);
      setResponse(`Error: ${error.response?.data || error.message}`);
    }
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      <h1>Cryptic Message using ECL-AKA</h1>
      <h3>Node B</h3>

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
          Generate Partial Public Keys
        </button>
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
        <button onClick={handleCheckMessage} style={buttonStyle}>
          Check Message
        </button>
      </div>

      {session && (
        <div style={{ marginBottom: "20px" }}>
          <h2>Send a Message</h2>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            style={textAreaStyle}
            placeholder="Enter your message here"
          />
          <button onClick={handleSendMessage} style={buttonStyle}>
            Send Message
          </button>
        </div>
      )}

      {/* {newMessage && (
        <div>
          <h2>New Message:</h2>
          <p>{newMessage}</p>
        </div>
      )} */}

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

const textAreaStyle = {
  width: "100%",
  height: "100px",
  marginBottom: "10px",
  padding: "10px",
  fontSize: "16px",
  borderRadius: "5px",
  border: "1px solid #DDD",
  resize: "none",
};

const responseStyle = {
  color: "black",
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
