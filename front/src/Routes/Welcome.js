import { Header } from "../Components/Header";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
function Welcome() {
    const [rightPageStyle, setRightPageStyle] = useState({
        width: "1px",
        height: "100vh",
        float: "right",
        backgroundColor: "black",
        display: "grid",
        placeItems: "center",
        minHeight: "100vh",
        color: "white",
    });
    const [leftPageStyle, setLeftPageStyle] = useState({
        width: "1px",
        height: "100vh",
        float: "left",
        backgroundColor: "black",
        placeItems: "center",
        minHeight: "100vh",
        color: "white",
    });

    const [unknownGif, setUnknownGif] = useState({
        width: "0px",
        marginTop: "50vh",
        opacity: "0"
    });

    const [buttonStyle, setButtonStyle] = useState({
        border: "none",
        borderRadius: "10px",
        color: "#fff",
        backgroundColor: "#000",
        width: "200px",
        height: "50px",
        marginTop: "100px",
        opacity: "0"
    })

    useEffect(() => {
        setTimeout(() => {
            setRightPageStyle({
                width: "50%",
                height: "100vh",
                float: "right",
                color: "black",
                backgroundColor: "white"
            });
            setLeftPageStyle({
                width: "50%",
                backgroundColor: "black",
                float: "left",
                color: "white"
            });
            setUnknownGif({
                width: "200px",
                marginTop: "30vh",
                opacity: "1"
            });
            setButtonStyle({
                border: "none",
                borderRadius: "10px",
                color: "#fff",
                backgroundColor: "#000",
                width: "200px",
                height: "50px",
                marginTop: "100px",
                opacity: "1"
            });
        }, 500)
    }, []);
    const navigate = useNavigate();
    const goToList = () => {
        navigate('/main');
    };
    return (
        <>
            <Header />
            <div className="left-page" style={leftPageStyle}>
                <div>
                    <img src={process.env.PUBLIC_URL + "/image_src/unknown.gif"} style={unknownGif} />
                </div>
                <br />
                <h2>이쁜 옷 찾았는데..<br />어디서 판매하는지 모르겠어요</h2>
            </div>
            <div className="right-page" style={rightPageStyle}>
                <div className="text" style={{ marginTop: '35vh' }}>
                    <h2>걱정마요! LYKYL가 있잖아요!</h2>
                    <h2>우리가 찾아줄게요!</h2>
                    <button type="button" style={buttonStyle} className="start-button" onClick={() => {
                        setRightPageStyle({
                            width: "1px",
                            height: "100vh",
                            float: "right",
                            backgroundColor: "white",
                            placeItems: "center",
                            minHeight: "100vh",
                            color: "white",
                        });
                        setLeftPageStyle({
                            width: "1px",
                            height: "100vh",
                            float: "left",
                            backgroundColor: "white",
                            placeItems: "center",
                            minHeight: "100vh",
                            color: "white",
                        });
                        setUnknownGif({
                            width: "0px",
                            marginTop: "30vh",
                            opacity: "0"
                        });
                        setButtonStyle({
                            border: "none",
                            borderRadius: "10px",
                            color: "#fff",
                            backgroundColor: "#000",
                            width: "200px",
                            height: "50px",
                            marginTop: "100px",
                            opacity: "0"
                        })
                        setTimeout(() => {
                            goToList();
                        }, 2000);
                    }}>찾으러 가기</button>
                </div>
            </div>
        </>
    )
};
export default Welcome;