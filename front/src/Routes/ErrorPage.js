import React from "react";
import { useNavigate } from "react-router-dom";

export default function NoPage() {
    const navigateToHome = useNavigate();
    const navigateToPrevious = useNavigate();

    const goToHome = () => {
        navigateToHome('/');
    }

    const goToPrevious = () => {
        navigateToPrevious(-1);
    }

    return (
        <>
        <div style={{marginTop: "150px"}}>
                <h1>Oops... You are in wrong page...</h1>
                <img src={process.env.PUBLIC_URL + "/image_src/404Error_Image.png"} 
                    style={{marginTop:"40px"}}
                ></img>
        </div>
        <div style={{marginTop: "40px"}}>
            <h2>Choose one !</h2>
            <button style={{
                marginTop:"20px",
                width:"250px",
                height:"70px",
                fontSize:"24px",
                fontWeight: "bold",
                background: "skyblue",
                borderRadius: "14px",
                color:"white",
                border:"none"
            }} onClick={() => {
                goToHome();
            }}>Back To Home</button>
            <button style={{
                marginLeft:"60px",
                marginTop:"20px",
                width:"250px",
                height:"70px",
                fontSize:"24px",
                fontWeight: "bold",
                background: "skyblue",
                borderRadius: "14px",
                color:"white",
                border:"none"
            }} onClick={() => {
                goToPrevious();
            }}>Back To Previous</button>
        </div>
        </>
    );
}