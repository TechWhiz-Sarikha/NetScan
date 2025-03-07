// Steps for User Guide (Floating Above Scan Page)
const steps = [
    { text: "Welcome to NetScanner! Click 'Next' to begin.", position: { top: "20px", left: "50%" } },
    { text: "Step 1: Enter the Target IP Address.", position: { top: "200px", left: "50%" } },
    { text: "Step 2: Select the scan type.", position: { top: "300px", left: "50%" } },
    { text: "Step 3: Click 'Start Scan' to begin.", position: { top: "400px", left: "50%" } },
    { text: "Step 4: View the scan results below.", position: { top: "500px", left: "50%" } },
    { text: "🎉 You've completed the guide!", position: { top: "20px", left: "50%" } }
];

let currentStep = 0;

// Function to update step text and cursor position
function updateStep() {
    const stepText = document.getElementById("step-text");
    const animatedCursor = document.getElementById("animated-cursor");

    stepText.textContent = steps[currentStep].text;
    animatedCursor.style.top = steps[currentStep].position.top;
    animatedCursor.style.left = steps[currentStep].position.left;

    // Disable/Enable buttons based on step position
    document.getElementById("prev-btn").disabled = currentStep === 0;
    document.getElementById("next-btn").disabled = currentStep === steps.length - 1;
}

// Next Step Button
function nextStep() {
    if (currentStep < steps.length - 1) {
        currentStep++;
        updateStep();
    }
}

// Previous Step Button
function prevStep() {
    if (currentStep > 0) {
        currentStep--;
        updateStep();
    }
}

// Initialize first step
window.onload = updateStep;
