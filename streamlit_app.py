import streamlit as st
import pandas as pd

# Set page configuration
st.set_page_config(
    page_title="MITRE ATLAS Matrix",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .tactic-header {
        background-color: #1E40AF;
        color: white;
        padding: 10px;
        border-radius: 5px 5px 0 0;
        margin-bottom: 0;
    }
    .technique-container {
        background-color: #F9FAFB;
        padding: 10px;
        border-radius: 0 0 5px 5px;
        border: 1px solid #E5E7EB;
        margin-top: 0;
    }
    .technique-item {
        background-color: white;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 8px;
        border: 1px solid #E5E7EB;
    }
    .technique-details {
        background-color: #F3F4F6;
        padding: 10px;
        border-radius: 5px;
        margin-top: 8px;
    }
    .badge {
        background-color: #E5E7EB;
        color: #4B5563;
        padding: 2px 6px;
        border-radius: 10px;
        font-size: 12px;
        font-family: monospace;
    }
    .mitigation-item {
        margin-left: 20px;
    }
    .main-header {
        color: #1E40AF;
    }
    .info-box {
        background-color: #EFF6FF;
        border: 1px solid #BFDBFE;
        border-radius: 5px;
        padding: 15px;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("<h1 class='main-header'>MITRE ATLAS™ Matrix</h1>", unsafe_allow_html=True)
st.markdown("### Adversarial Threat Landscape for Artificial-Intelligence Systems")
st.markdown("A knowledge base of adversary tactics, techniques, and case studies for AI systems")

# Information box with expander
with st.expander("About MITRE ATLAS™"):
    st.markdown("""
    **MITRE ATLAS™** (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge base documenting tactics, techniques, and case studies for adversaries targeting AI systems.
    
    Originally launched in June 2021, ATLAS extends MITRE's ATT&CK® framework to address the unique security challenges of AI and machine learning systems. The framework helps organizations understand, detect, and mitigate threats against their AI investments.
    
    **Key Components:**
    - **Tactics:** High-level objectives of adversaries (the "why")
    - **Techniques:** Methods used to achieve these objectives (the "how")
    - **Mitigations:** Defensive measures to counter specific techniques
    - **Case Studies:** Real-world examples of attacks against AI systems
    
    ATLAS is designed to be a living framework that evolves as new threats emerge and as AI technologies continue to develop. It serves as a common language for security professionals, AI developers, and organizations to discuss and address the security challenges unique to artificial intelligence.
    
    [Visit the official MITRE ATLAS website](https://atlas.mitre.org)
    """)

# ATLAS tactics
tactics = [
    { 
        "id": "TA01", 
        "name": "Reconnaissance",
        "description": "Gather information about the target AI system to plan attacks."
    },
    { 
        "id": "TA02", 
        "name": "Resource Development",
        "description": "Establish resources needed to support operations against AI systems."
    },
    { 
        "id": "TA03", 
        "name": "Initial Access",
        "description": "Gain access to the AI infrastructure or system."
    },
    { 
        "id": "TA04", 
        "name": "ML Model Access",
        "description": "Obtain access to the machine learning model itself."
    },
    { 
        "id": "TA05", 
        "name": "Persistence",
        "description": "Maintain access to the AI system."
    },
    { 
        "id": "TA06", 
        "name": "Privilege Escalation",
        "description": "Gain higher-level permissions within the AI system."
    },
    { 
        "id": "TA07", 
        "name": "Defense Evasion",
        "description": "Avoid detection of adversarial activities."
    },
    { 
        "id": "TA08", 
        "name": "Credential Access",
        "description": "Obtain credentials to access AI systems."
    },
    { 
        "id": "TA09", 
        "name": "Discovery",
        "description": "Explore the AI environment and discover vulnerabilities."
    },
    { 
        "id": "TA10", 
        "name": "Collection",
        "description": "Gather valuable data from the AI system."
    },
    { 
        "id": "TA11", 
        "name": "ML Attack Stage",
        "description": "Deploy attacks against machine learning models."
    },
    { 
        "id": "TA12", 
        "name": "Exfiltration",
        "description": "Steal data from the AI system."
    },
    { 
        "id": "TA13", 
        "name": "Impact",
        "description": "Manipulate, interrupt, or destroy AI systems and data."
    },
    { 
        "id": "TA14", 
        "name": "Model Compromise",
        "description": "Compromise the integrity or operation of ML models."
    }
]

# Sample techniques for each tactic
techniques = {
    'TA01': [
        { "id": "T0001", "name": "AI-Enabled Scanning", "description": "Use AI tools to scan for vulnerable AI systems or components." },
        { "id": "T0002", "name": "Model Reconnaissance", "description": "Gather information about the target ML model such as architecture, parameters, or inputs." },
        { "id": "T0003", "name": "Data Reconnaissance", "description": "Gather information about the data used to train or operate the AI system." }
    ],
    'TA02': [
        { "id": "T0004", "name": "Acquire ML Infrastructure", "description": "Obtain compute resources or tools needed for attacking AI systems." },
        { "id": "T0005", "name": "Develop Adversarial ML Capability", "description": "Build or acquire tools for creating adversarial examples or other ML attacks." },
        { "id": "T0006", "name": "Obtain ML Training Data", "description": "Acquire data similar to what was used to train the target model." }
    ],
    'TA03': [
        { "id": "T0007", "name": "ML API Access", "description": "Gain access to ML system APIs." },
        { "id": "T0008", "name": "Supply Chain Compromise", "description": "Compromise the ML supply chain (pre-trained models, libraries, or datasets)." },
        { "id": "T0009", "name": "Exploit Public-Facing ML Service", "description": "Exploit vulnerabilities in publicly accessible ML services." }
    ],
    'TA04': [
        { "id": "T0010", "name": "Obtain ML Model", "description": "Acquire the ML model through legitimate or illegitimate means." },
        { "id": "T0011", "name": "Model Inference API Access", "description": "Gain access to APIs that allow queries to the model." },
        { "id": "T0012", "name": "Model Repository Access", "description": "Access repositories where models are stored." }
    ],
    'TA05': [
        { "id": "T0013", "name": "Backdoor ML Model", "description": "Insert hidden functionality into ML models." },
        { "id": "T0014", "name": "Persistent ML API Access", "description": "Maintain ongoing access to ML APIs." },
        { "id": "T0015", "name": "Compromise ML Development Environment", "description": "Gain persistent access to environments where models are developed." }
    ],
    'TA06': [
        { "id": "T0016", "name": "Escalate ML API Privileges", "description": "Increase privileges within ML service APIs." },
        { "id": "T0017", "name": "ML System Privilege Escalation", "description": "Gain higher permissions within the ML system infrastructure." }
    ],
    'TA07': [
        { "id": "T0018", "name": "Evade ML Detection Models", "description": "Avoid detection by ML-based security systems." },
        { "id": "T0019", "name": "Manipulate ML Training Data", "description": "Subtly alter training data to evade detection." },
        { "id": "T0020", "name": "Evade Model Analysis", "description": "Avoid techniques used to analyze model behavior and security." }
    ],
    'TA08': [
        { "id": "T0021", "name": "ML API Key Theft", "description": "Steal authentication keys for ML services." },
        { "id": "T0022", "name": "ML Infrastructure Credential Access", "description": "Obtain credentials for ML infrastructure systems." }
    ],
    'TA09': [
        { "id": "T0023", "name": "ML Model Probing", "description": "Query ML models to learn about their behavior." },
        { "id": "T0024", "name": "ML Architecture Discovery", "description": "Determine the architecture or structure of ML models." },
        { "id": "T0025", "name": "ML Model Fingerprinting", "description": "Identify specific ML models or versions through their unique behaviors." }
    ],
    'TA10': [
        { "id": "T0026", "name": "Training Data Collection", "description": "Collect data used to train ML models." },
        { "id": "T0027", "name": "Model Output Collection", "description": "Collect and analyze outputs from ML models." },
        { "id": "T0028", "name": "Model Parameter Collection", "description": "Extract model parameters or weights." }
    ],
    'TA11': [
        { "id": "T0029", "name": "Model Poisoning", "description": "Manipulate ML models during training to introduce vulnerabilities." },
        { "id": "T0030", "name": "Adversarial Examples", "description": "Create inputs specifically designed to cause ML models to make mistakes." },
        { "id": "T0031", "name": "Model Inversion Attack", "description": "Extract training data by analyzing model responses." },
        { "id": "T0032", "name": "Model Evasion", "description": "Modify inputs to evade correct classification by ML models." }
    ],
    'TA12': [
        { "id": "T0033", "name": "Exfiltrate ML Model", "description": "Steal ML models from the target environment." },
        { "id": "T0034", "name": "Exfiltrate Training Data", "description": "Steal data used to train ML models." },
        { "id": "T0035", "name": "Exfiltrate Inferred Data", "description": "Extract sensitive information from model outputs." }
    ],
    'TA13': [
        { "id": "T0036", "name": "ML-Generated Disinformation", "description": "Use ML to create convincing false information." },
        { "id": "T0037", "name": "Denial of ML Service", "description": "Disrupt ML services, making them unavailable." },
        { "id": "T0038", "name": "ML Output Manipulation", "description": "Cause ML systems to produce manipulated or harmful outputs." }
    ],
    'TA14': [
        { "id": "T0039", "name": "Model Theft", "description": "Steal or reproduce proprietary ML models." },
        { "id": "T0040", "name": "Model Corruption", "description": "Corrupt ML models to degrade performance or inject vulnerabilities." },
        { "id": "T0041", "name": "Model Backdooring", "description": "Insert hidden functionality that can be triggered under specific conditions." }
    ]
}

# Mitigations for each technique
mitigations = {
    'T0001': ['Input validation', 'Network monitoring', 'Access controls'],
    'T0002': ['Model obfuscation', 'Limited API access', 'Federated learning'],
    'T0003': ['Data access controls', 'Data anonymization', 'Monitoring unusual queries'],
    'T0004': ['Cloud security', 'Resource access monitoring', 'Infrastructure hardening'],
    'T0005': ['Security testing', 'Adversarial training', 'Threat intelligence'],
    'T0006': ['Data encryption', 'Access controls', 'Data watermarking'],
    'T0007': ['Rate limiting', 'API authentication', 'Request monitoring'],
    'T0008': ['Vendor assessment', 'Integrity verification', 'Security testing'],
    'T0009': ['Input validation', 'Rate limiting', 'Anomaly detection'],
    'T0010': ['Model encryption', 'Access controls', 'Watermarking'],
    'T0011': ['Authentication', 'Rate limiting', 'Output filtering'],
    'T0012': ['Access controls', 'Audit logging', 'Encryption'],
    'T0013': ['Model verification', 'Anomaly detection', 'Regular testing'],
    'T0014': ['Token revocation', 'Access monitoring', 'Periodic credential rotation'],
    'T0015': ['Environment hardening', 'Access controls', 'Change monitoring'],
    'T0016': ['Least privilege principle', 'Role-based access control', 'Activity monitoring'],
    'T0017': ['Segregation of duties', 'System hardening', 'Intrusion detection'],
    'T0018': ['Ensemble detection', 'Diversity training', 'Adversarial training'],
    'T0019': ['Data provenance', 'Data validation', 'Anomaly detection'],
    'T0020': ['Multiple analysis techniques', 'Black-box testing', 'Sandboxing'],
    'T0021': ['Secure key management', 'Key rotation', 'Access monitoring'],
    'T0022': ['Multi-factor authentication', 'Least privilege', 'Credential monitoring'],
    'T0023': ['Rate limiting', 'Query analysis', 'Access controls'],
    'T0024': ['Model obfuscation', 'Limited output information', 'Query monitoring'],
    'T0025': ['Model versioning', 'Response randomization', 'Output perturbation'],
    'T0026': ['Data access controls', 'Audit logging', 'Honeypot data'],
    'T0027': ['Output limiting', 'Response sanitization', 'Monitoring'],
    'T0028': ['Model encryption', 'Differential privacy', 'Parameter obfuscation'],
    'T0029': ['Data validation', 'Anomaly detection', 'Regular retraining'],
    'T0030': ['Adversarial training', 'Input preprocessing', 'Multiple model validation'],
    'T0031': ['Differential privacy', 'Output limiting', 'Confidence thresholds'],
    'T0032': ['Robust training', 'Input validation', 'Ensemble models'],
    'T0033': ['Model encryption', 'Access controls', 'Monitoring'],
    'T0034': ['Data encryption', 'Access controls', 'Data watermarking'],
    'T0035': ['Output limiting', 'Information filtering', 'Query analysis'],
    'T0036': ['Output validation', 'Content verification', 'Human review'],
    'T0037': ['Resource scaling', 'Rate limiting', 'Redundancy'],
    'T0038': ['Output validation', 'Multiple model verification', 'Anomaly detection'],
    'T0039': ['Watermarking', 'Model encryption', 'API rate limiting'],
    'T0040': ['Integrity checking', 'Regular testing', 'Secure deployment'],
    'T0041': ['Model verification', 'Regular testing', 'Input scanning']
}

# Create columns for better layout
col1, col2 = st.columns([1, 3])

# Sidebar for tactic selection
with col1:
    st.markdown("## Tactics")
    selected_tactic = st.radio(
        "Select a tactic to view its techniques:",
        options=[f"{t['id']}: {t['name']}" for t in tactics],
        label_visibility="collapsed"
    )
    
    # Get the selected tactic ID
    selected_tactic_id = selected_tactic.split(":")[0].strip()
    
    # Display tactic description
    selected_tactic_info = next((t for t in tactics if t["id"] == selected_tactic_id), None)
    if selected_tactic_info:
        st.info(selected_tactic_info["description"])

# Main content area for techniques
with col2:
    st.markdown(f"## {selected_tactic}")
    
    # Get techniques for the selected tactic
    tactic_techniques = techniques.get(selected_tactic_id, [])
    
    if not tactic_techniques:
        st.warning("No techniques available for this tactic.")
    else:
        # Create tabs for each technique
        technique_tabs = st.tabs([f"{t['id']}: {t['name']}" for t in tactic_techniques])
        
        # Populate each tab with technique details
        for i, tab in enumerate(technique_tabs):
            with tab:
                technique = tactic_techniques[i]
                st.markdown(f"### {technique['name']}")
                st.markdown(f"**ID:** `{technique['id']}`")
                st.markdown(f"**Description:** {technique['description']}")
                
                # Display mitigations
                st.markdown("### Mitigations")
                technique_mitigations = mitigations.get(technique['id'], [])
                if technique_mitigations:
                    for mitigation in technique_mitigations:
                        st.markdown(f"- {mitigation}")
                else:
                    st.warning("No mitigations available for this technique.")

# Add a footer
st.markdown("---")
st.markdown("This interactive MITRE ATLAS Matrix is a visualization tool for understanding AI security threats. For official and complete information, please visit [atlas.mitre.org](https://atlas.mitre.org).")