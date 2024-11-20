import logo from './logo.svg';
import './App.css';
import axios from 'axios';
import React,{useEffect} from 'react';

function App() {

  const test = () => {
    const data = {
      username: "hope",
      password: "Johnhope@2002"
    }
    // const data ={
    //   privateKey: "XERA07f3d7bdb1b75c03aaba9a9212f41644c1cf1ad9c2c6fedc770608031ce5"
    // }
    // const data ={
    //   seedWord1: "chair",
    //   seedWord2: "emerald",
    //   seedWord3: "fan",
    //   seedWord4: "frost",
    //   seedWord5: "drums",
    //   seedWord6: "shrimp",
    //   seedWord7: "sunrise",
    //   seedWord8: "oats",
    //   seedWord9: "haze",
    //   seedWord10: "chair",
    //   seedWord11: "treetop",
    //   seedWord12: "plastic"
    // }

    // const seedPhrase = JSON.stringify(data)
    axios 
      .post("https://texeract.network/xera/api/login-basic",data)
      .then((res) => {
        console.log(res);
      })
      .catch((err) => {
        alert(err.response.data.message)
      })
  }
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
        <button onClick={test}>test</button>
      </header>
    </div>
  );
}

export default App;
