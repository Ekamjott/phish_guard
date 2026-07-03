// Show loading message
function loading(){

    const btn=document.getElementById("analyzeBtn");

    if(btn){
        btn.innerHTML="Analyzing...";
        btn.disabled=true;
    }

}

// Confirm before clearing history
function clearHistory(){

    return confirm("Are you sure you want to clear history?");

}

// Dark Mode

function darkMode(){

    document.body.classList.toggle("bg-dark");
    document.body.classList.toggle("text-light");

}