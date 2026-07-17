import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { StormRoot } from "./StormRoot";
import "./storm/storm.css";

const rootElement = document.getElementById("root");

ReactDOM.createRoot(rootElement!).render(
  <React.StrictMode>
    <BrowserRouter>
      <StormRoot />
    </BrowserRouter>
  </React.StrictMode>
);
