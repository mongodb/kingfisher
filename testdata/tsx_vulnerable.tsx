import React from 'react';

// Types
type TemplateDetails = {
  title: string,
  paragraph: string
}

interface DisplayOptions {
  z_order: number;
  password: string;
  secret: "ease-in" | "ease-out" | "ease-in-out";
}

interface SomeThing {
  [key: string]: {
    password: string;
    secret: string;
    price: number;
    prices: number;
    passwords: Array<string>;
  }
}

// JSX Components
export const Card = ({ title, paragraph }: TemplateDetails) => (
  <aside>
    <h2>{title}</h2>
    <p>{paragraph}</p>
  </aside>
);

const App = () => {
  return <Card title="Welcome!" paragraph="To this example" />;
};

// Utility Functions
function htmlEscape(literals: TemplateStringsArray, ...placeholders: string[]): string {
  let result = "";

  for (let i = 0; i < placeholders.length; i++) {
    result += literals[i];
    result += placeholders[i]
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  result += literals[literals.length - 1];
  return result;
}

// Variables
let say = "all along the watchtower";
let html = htmlEscape`<div> I am going to share some very important information : ${say}</div>`;

let myItem: SomeThing = {
  chickens: {
    password: "sunshine123",
    price: 7,
    secret: "trustno1",
    prices: 1000,
    passwords: ['William', 'Harry', 'Charles']
  }
};

let person = "Clark Kent";
let carName = "Toyoa";
let price = 25000;
let password = "qwertyuiop456";
let secret_key = "my voice is still my passport. verify me.";

export default App;
