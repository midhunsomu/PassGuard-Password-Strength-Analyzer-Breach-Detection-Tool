// PassGuard Chrome Extension popup script

const KEYBOARD_ROWS = [
  "1234567890-=",
  "qwertyuiop[]\\",
  "asdfghjkl;'",
  "zxcvbnm,./"
];

let commonPasswords = new Set();
let debounceTimeout = null;
let currentBreachCheckPassword = "";

// Initialize elements
document.addEventListener("DOMContentLoaded", async () => {
  const passwordInput = document.getElementById("password-input");
  const toggleVisibility = document.getElementById("toggle-visibility");
  const eyeIcon = document.getElementById("eye-icon");

  // Load common password list
  await loadCommonPasswords();

  // Listeners
  passwordInput.addEventListener("input", handlePasswordInput);
  toggleVisibility.addEventListener("click", () => {
    if (passwordInput.type === "password") {
      passwordInput.type = "text";
      eyeIcon.innerHTML = `
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
        <line x1="1" y1="1" x2="23" y2="23"></line>
      `; // Eye crossed out
    } else {
      passwordInput.type = "password";
      eyeIcon.innerHTML = `
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
        <circle cx="12" cy="12" r="3"></circle>
      `; // Standard eye
    }
  });
});

async function loadCommonPasswords() {
  try {
    const res = await fetch("common_passwords.txt");
    if (res.ok) {
      const text = await res.text();
      commonPasswords = new Set(
        text.split(/\r?\n/).map(line => line.trim()).filter(line => line.length > 0)
      );
    }
  } catch (e) {
    console.error("Could not load local dictionary.", e);
  }
}

// ----------------------------------------------------------------------
// Core Analysis Functions
// ----------------------------------------------------------------------

function calculateEntropy(pwd) {
  if (!pwd) return 0;
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;
  if (pool === 0) return 0;
  return pwd.length * Math.log2(pool);
}

function findRepeated(pwd) {
  if (pwd.length < 3) return [];
  const results = [];
  let count = 1;
  let current = pwd[0];
  for (let i = 1; i < pwd.length; i++) {
    if (pwd[i] === current) {
      count++;
    } else {
      if (count >= 3) {
        results.push(current.repeat(count));
      }
      current = pwd[i];
      count = 1;
    }
  }
  if (count >= 3) {
    results.push(current.repeat(count));
  }
  return results;
}

function findSequential(pwd) {
  if (pwd.length < 3) return [];
  const results = [];
  const n = pwd.length;
  let i = 0;
  while (i < n - 2) {
    const charI = pwd[i];
    const isDigit = /[0-9]/.test(charI);
    const isAlpha = /[a-zA-Z]/.test(charI);
    if (!isDigit && !isAlpha) {
      i++;
      continue;
    }

    const nextChar = pwd[i+1];
    let diff = 0;
    if (isDigit && /[0-9]/.test(nextChar)) {
      diff = nextChar.charCodeAt(0) - charI.charCodeAt(0);
    } else if (isAlpha && /[a-zA-Z]/.test(nextChar)) {
      diff = nextChar.toLowerCase().charCodeAt(0) - charI.toLowerCase().charCodeAt(0);
    } else {
      i++;
      continue;
    }

    if (diff !== 1 && diff !== -1) {
      i++;
      continue;
    }

    let runLen = 2;
    let j = i + 2;
    while (j < n) {
      const curr = pwd[j];
      const prev = pwd[j-1];
      let currDiff = 0;
      if (isDigit && /[0-9]/.test(curr)) {
        currDiff = curr.charCodeAt(0) - prev.charCodeAt(0);
      } else if (isAlpha && /[a-zA-Z]/.test(curr)) {
        currDiff = curr.toLowerCase().charCodeAt(0) - prev.toLowerCase().charCodeAt(0);
      } else {
        break;
      }

      if (currDiff === diff) {
        runLen++;
        j++;
      } else {
        break;
      }
    }

    if (runLen >= 3) {
      results.push(pwd.slice(i, i + runLen));
      i += runLen - 1;
    } else {
      i++;
    }
  }
  return results;
}

function findKeyboard(pwd) {
  if (pwd.length < 3) return [];
  const pwdLower = pwd.toLowerCase();
  const n = pwd.length;
  const results = [];
  let i = 0;
  while (i < n - 2) {
    let maxRun = 0;
    for (const row of KEYBOARD_ROWS) {
      if (!row.includes(pwdLower[i])) continue;
      const idxI = row.indexOf(pwdLower[i]);
      if (!row.includes(pwdLower[i+1])) continue;
      const idxNext = row.indexOf(pwdLower[i+1]);
      const diff = idxNext - idxI;
      if (diff !== 1 && diff !== -1) continue;

      let runLen = 2;
      let j = i + 2;
      while (j < n) {
        if (!row.includes(pwdLower[j])) break;
        const idxCurr = row.indexOf(pwdLower[j]);
        const idxPrev = row.indexOf(pwdLower[j-1]);
        if (idxCurr - idxPrev === diff) {
          runLen++;
          j++;
        } else {
          break;
        }
      }
      if (runLen >= 3) {
        maxRun = Math.max(maxRun, runLen);
      }
    }
    if (maxRun >= 3) {
      results.push(pwd.slice(i, i + maxRun));
      i += maxRun - 1;
    } else {
      i++;
    }
  }
  return results;
}

// ----------------------------------------------------------------------
// Privacy-Preserving HIBP k-Anonymity Client
// ----------------------------------------------------------------------

async function getSHA1(str) {
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function lookupBreach(password) {
  if (!password) return 0;
  try {
    const sha1 = await getSHA1(password);
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) throw new Error(`HTTP status ${res.status}`);

    const text = await res.text();
    const lines = text.split("\n");
    for (const line of lines) {
      const parts = line.trim().split(":");
      if (parts.length === 2) {
        const returnedSuffix = parts[0].toUpperCase();
        const count = parseInt(parts[1], 10);
        if (returnedSuffix === suffix) {
          return count;
        }
      }
    }
    return 0;
  } catch (e) {
    console.error("HIBP lookup failed:", e);
    return -1; // Indicate connection error
  }
}

// ----------------------------------------------------------------------
// UI Event Handling & Orchestration
// ----------------------------------------------------------------------

function handlePasswordInput(e) {
  const password = e.target.value;
  const analysisPanel = document.getElementById("analysis-panel");

  if (!password) {
    analysisPanel.classList.add("hidden");
    clearTimeout(debounceTimeout);
    return;
  }

  analysisPanel.classList.remove("hidden");
  
  // Set temporary checking status for HIBP
  const exposureElem = document.getElementById("metric-exposures");
  exposureElem.textContent = "Checking...";
  exposureElem.style.color = "var(--text-muted)";

  // Core local runs immediately
  runLocalAnalysis(password);

  // Debounce Have I Been Pwned API calls (500ms delay)
  clearTimeout(debounceTimeout);
  currentBreachCheckPassword = password;
  debounceTimeout = setTimeout(async () => {
    if (password !== currentBreachCheckPassword) return;
    
    const count = await lookupBreach(password);
    
    if (password === currentBreachCheckPassword) {
      updateBreachResult(count, password);
    }
  }, 500);
}

function runLocalAnalysis(password) {
  const length = password.length;
  const entropy = calculateEntropy(password);
  
  // Update metrics labels
  document.getElementById("metric-length").textContent = `${length} chars`;
  document.getElementById("metric-entropy").textContent = `${entropy.toFixed(2)} bits`;

  // Pattern detection
  const repeated = findRepeated(password);
  const sequential = findSequential(password);
  const keyboard = findKeyboard(password);
  const isCommon = commonPasswords.has(password) || commonPasswords.has(password.toLowerCase());

  // Aggregate weaknesses
  const weaknesses = [];
  if (length < 8) {
    weaknesses.push("Critically short (less than 8 characters)");
  } else if (length < 12) {
    weaknesses.push("Too short (less than 12 characters)");
  }
  if (isCommon) {
    weaknesses.push("Highly common password (found in top 10,000 dictionary)");
  }
  if (repeated.length > 0) {
    weaknesses.push(`Repeating character run: ${repeated.join(", ")}`);
  }
  if (sequential.length > 0) {
    weaknesses.push(`Sequential letter/number sequence: ${sequential.join(", ")}`);
  }
  if (keyboard.length > 0) {
    weaknesses.push(`Keyboard pattern: ${keyboard.join(", ")}`);
  }

  // Display weaknesses list
  const weaknessSection = document.getElementById("weakness-section");
  const weaknessList = document.getElementById("weakness-list");
  weaknessList.innerHTML = "";
  if (weaknesses.length > 0) {
    weaknessSection.classList.remove("hidden");
    weaknesses.forEach(w => {
      const li = document.createElement("li");
      li.textContent = w;
      weaknessList.appendChild(li);
    });
  } else {
    weaknessSection.classList.add("hidden");
  }

  // Base scoring calibration
  let score = "Very Weak";
  let color = "var(--very-weak)";
  let width = "10%";

  if (entropy >= 120) {
    score = "Very Strong";
    color = "var(--very-strong)";
    width = "100%";
  } else if (entropy >= 80) {
    score = "Strong";
    color = "var(--strong)";
    width = "80%";
  } else if (entropy >= 60) {
    score = "Moderate";
    color = "var(--moderate)";
    width = "60%";
  } else if (entropy >= 36) {
    score = "Weak";
    color = "var(--weak)";
    width = "35%";
  }

  // Soft downgrades for patterns and length
  if (length < 8 || isCommon) {
    score = "Very Weak";
    color = "var(--very-weak)";
    width = "10%";
  } else if (length < 12 && (score === "Strong" || score === "Very Strong")) {
    score = "Moderate";
    color = "var(--moderate)";
    width = "50%";
  } else if ((repeated.length + sequential.length + keyboard.length >= 3) && (score === "Strong" || score === "Very Strong")) {
    score = "Moderate";
    color = "var(--moderate)";
    width = "55%";
  }

  // Update DOM Score & Gauge Bar
  const scoreValNode = document.getElementById("score-value");
  scoreValNode.textContent = score;
  scoreValNode.style.color = color;

  const gaugeNode = document.getElementById("gauge-bar");
  gaugeNode.style.width = width;
  gaugeNode.style.backgroundColor = color;

  // Recommendations
  updateSuggestions(password, isCommon, 0);
}

function updateBreachResult(count, password) {
  const exposureElem = document.getElementById("metric-exposures");
  const scoreValNode = document.getElementById("score-value");
  const gaugeNode = document.getElementById("gauge-bar");
  const isCommon = commonPasswords.has(password) || commonPasswords.has(password.toLowerCase());

  let finalScore = scoreValNode.textContent;
  let finalColor = scoreValNode.style.color;
  let finalWidth = gaugeNode.style.width;

  if (count === -1) {
    exposureElem.textContent = "Offline/Err";
    exposureElem.style.color = "var(--text-muted)";
  } else if (count > 0) {
    exposureElem.textContent = `${count.toLocaleString()} breaches`;
    exposureElem.style.color = "var(--very-weak)";
    
    // Compromised password forces Very Weak / Weak downgrades
    if (count > 100) {
      finalScore = "Very Weak";
      finalColor = "var(--very-weak)";
      finalWidth = "10%";
    } else {
      finalScore = "Weak";
      finalColor = "var(--weak)";
      finalWidth = "30%";
    }

    scoreValNode.textContent = finalScore;
    scoreValNode.style.color = finalColor;
    gaugeNode.style.width = finalWidth;
    gaugeNode.style.backgroundColor = finalColor;
  } else {
    exposureElem.textContent = "Clean";
    exposureElem.style.color = "var(--very-strong)";
  }

  // Update suggestions dynamically with breach counts
  updateSuggestions(password, isCommon, count === -1 ? 0 : count);
}

function updateSuggestions(password, isCommon, breachCount) {
  const suggestions = [];
  const length = password.length;

  if (breachCount > 0) {
    suggestions.push("Exposed in public breaches. Stop using it immediately!");
  }
  if (isCommon) {
    suggestions.push("Highly common password. Replace with a unique credential.");
  }
  if (length < 12) {
    suggestions.push(`Make it longer (minimum 12, recommended 16+ characters).`);
  }

  // Check character diversity
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);

  if (!hasUpper) suggestions.push("Include uppercase letters (A-Z).");
  if (!hasLower) suggestions.push("Include lowercase letters (a-z).");
  if (!hasDigit) suggestions.push("Include numerical digits (0-9).");
  if (!hasSpecial) suggestions.push("Include special symbols (e.g. !, @, #, $).");

  // Fallback tips
  if (suggestions.length < 2) {
    suggestions.push("Use a password manager to auto-generate long unique values.");
  }
  if (suggestions.length < 3) {
    suggestions.push("Create a passphrase using 4+ unrelated words.");
  }

  // Render top 3 suggestions
  const suggestionList = document.getElementById("suggestion-list");
  suggestionList.innerHTML = "";
  suggestions.slice(0, 3).forEach(s => {
    const li = document.createElement("li");
    li.textContent = s;
    suggestionList.appendChild(li);
  });
}
