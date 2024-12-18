# Cryptography-Project
College Cryptography Project

G-5
Akansh Vaibhav - S20210010010
Akash Singh Narvariya - S20210010012


Running Instructions :

1) Making a Python Virtual Enviorenment :
Run the following command to make Python venv :

        python -m venv venv

Command to Activzte venv (Must activate before running any command) :


        .\venv\Scripts\Activate


2) Installing Dependencies in Venv
Run the following command to install dependencies :


       .\venv\Scripts\Activate
        pip install -r requirement.txt

Run the following command to install Frontend Dependencies :
    
    cd .\frontendA\
    npm install

    cd .\frontendB\
    npm install


3) Running Servers 
You Need to Open 5 Terminals/ Servers to run the project

Terminal 1 (Server/KGC)
    Run the following commands :
    
    .\venv\Scripts\Activate
    uvicorn Server:app --port 8000 --reload

Terminal 2 (Node A Backend)
    Run the following commands :
    
    .\venv\Scripts\Activate
    uvicorn nodeA:app --port 8001 --reload

Terminal 3 (Node B Backend)
    Run the following commands :
    
    .\venv\Scripts\Activate
    uvicorn nodeB:app --port 8002 --reload

Temrinal 4 (Node A Frontend)
    Run the following commands :
    
    .\venv\Scripts\Activate
    npm run dev

Terminal 5 (Node B Frontend)
    Run the following commands :
    
    .\venv\Scripts\Activate
    npm run dev


4) Test The Project :

    -Fetch Server Info
    -Generate keys
    -Generate Partial Keys

    These Three buttons can be tested alone by running Single Node and Server

    -Authenticate
    -Generate Session Key
    -Check Mesaage

    These buttons will only give correct output when the Node B is also running and have generated its Keys as well
