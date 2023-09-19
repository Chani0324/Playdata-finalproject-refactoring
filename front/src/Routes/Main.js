import React, { useEffect, useRef, useState } from "react";
import { useMediaQuery } from "react-responsive";
import DragAndDrop from "../Components/Upload";

const Desktop = ({ children }) => {
    const isDesktop = useMediaQuery({ minWidth: 1025 })
    return isDesktop ? children : null
}
const Tablet = ({ children }) => {
    const isTablet = useMediaQuery({ minWidth: 820, maxWidth: 1024 })
    return isTablet ? children : null
}
const Mobile = ({ children }) => {
    const isMobile = useMediaQuery({ maxWidth: 819 })
    return isMobile ? children : null
}

function UploadArea(props) {

    var guidelineTitle = [
        "사진을 통해 제품 찾기", "이런 것들을 찾아드려요"
    ];
    var guidelineContent = [
        `위의 박스에 사용자의 이미지 파일을 드래그 앤 드롭 또는 버튼을 눌러 업로드하세요.
        이미지 파일을 업로드 해주시면, 저희 인공지능 기술로 이미지 안에서 
        감지된 옷을 통해 유사한 옷들을 검색하여 찾아드려요!`,
        `이미지 파일에서 감지된 옷들을 카테고리 별로 검색해 드려요!
        저희는 상의 계열, 하의 계열 카테고리를 검색해 드릴 수 있어요.
        검색된 결과가 화면에 출력되면 버튼을 눌러 카테고리 별로 구경하실 수 있어요!`
    ];

    return (
        <>
            <Desktop>
                <div>
                    <DragAndDrop />
                    <div className="parent"
                        style={{
                            width: "70%",
                            display: "flex",
                            margin: "6em 15% 0 15%",
                            position: "relative"

                        }}>
                        {guidelineTitle.map((a, i) => {
                            return (
                                <div className="child" style={{ background: "none", flex: "1" }} key={i}>
                                    <img src={process.env.PUBLIC_URL + "/image_src/guideline_image" + (i + 1) + ".png"} style={{ width: "5.3em", height: "5.2em" }} />
                                    <h4 style={{ marginTop: "1vh" }}>{guidelineTitle[i]}</h4>
                                    <p style={{ fontSize: "1.2em", marginTop: "1vh", width: "75%", marginLeft: "12.5%" }}>
                                        {guidelineContent[i]}
                                    </p>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </Desktop>
            <Tablet>
                <DragAndDrop />
                <div className="parent"
                    style={{
                        width: "70%",
                        display: "flex",
                        margin: "6em 15% 0 15%",
                        position: "relative"
                    }}>
                    {guidelineTitle.map((a, i) => {
                        if (i < 2) {
                            return (
                                <div className="child" style={{ background: "none", flex: "1", minHeight: "33em" }} key={i}>
                                    <img src={process.env.PUBLIC_URL + "/image_src/guideline_image" + (i+1) + ".png"} style={{ width: "5.3em", height: "5.2em" }} />
                                    <h4 style={{ marginTop: "1em" }}>{guidelineTitle[i]}</h4>
                                    <p style={{ fontSize: "1.2em", marginTop: "1vh", width: "75%", marginLeft: "12.5%" }}>
                                        {guidelineContent[i]}
                                    </p>
                                </div>
                            );
                        }
                    })}
                </div>
                <div className="parent"
                    style={{
                        width: "40%",
                        display: "flex",
                        margin: "-10vh 30% 0 30%",
                        position: "relative"
                    }}>
                    {guidelineTitle.map((a, i) => {
                        if (i >= 2 && i < 4) {
                            return (
                                <div className="child" style={{ background: "none", flex: "1" }} key={i}>
                                    <img src={process.env.PUBLIC_URL + "/image_src/guideline_image" + (i + 1) + ".png"} style={{ width: "5.3em", height: "5.2em" }} />
                                    <h4 style={{ marginTop: "1em" }}>{guidelineTitle[i]}</h4>
                                    <p style={{ fontSize: "1.2em", marginTop: "1vh", width: "75%", marginLeft: "12.5%" }}>
                                        {guidelineContent[i]}
                                    </p>
                                </div>
                            );
                        }
                    })}
                </div>
            </Tablet>
            <Mobile>
                <DragAndDrop />
                <div className="parent"
                    style={{
                        width: "70%",
                        display: "flex",
                        margin: "4em 15% 0 15%",
                        position: "relative"
                    }}>
                    <div className="child" style={{ background: "none", minHeight: "28em" }} >
                        <img src={process.env.PUBLIC_URL + "/image_src/guideline_image1.png"} style={{ width: "5.3em", height: "5.2em" }} />
                        <h4 style={{ marginTop: "1em" }}>{guidelineTitle[0]}</h4>
                        <p style={{ fontSize: "1.2em", marginTop: "1vh", width: "75%", marginLeft: "12.5%" }}>
                            {guidelineContent[0]}
                        </p>
                    </div>
                </div>
                {guidelineTitle.map((a, i) => {
                    if (i > 0) {
                        return (
                            <div className="parent"
                                style={{
                                    width: "80%",
                                    margin: "-8vh 10% 0 10%",
                                }} key={i}>
                                <div className="child" style={{ background: "none", minHeight: "28em" }} >
                                    <img src={process.env.PUBLIC_URL + "/image_src/guideline_image" + (i + 1) + ".png"} style={{ width: "5.3em", height: "5.2em" }} />
                                    <h4 style={{ marginTop: "1em" }}>{guidelineTitle[i]}</h4>
                                    <p style={{ fontSize: "1.2em", marginTop: "1vh", width: "75%", marginLeft: "12.5%" }}>
                                        {guidelineContent[i]}
                                    </p>
                                </div>
                            </div>
                        );
                    }
                })}
            </Mobile>
        </>
    );
}




function Banner() {

    const bannerImgArray = ['playdata_ad_banner2.png', 'playdata_ad_banner1.png']
    const [count, setCount] = useState(0)

    const changeState = useRef();
    const boolean = useRef(true);

    function callback() {
        setCount(count + 1);
    }

    useEffect(() => {
        changeState.current = callback;
    })

    useEffect(() => {
        const timer = setInterval(() => {
            if (count === 1) {
                boolean.current = false;
                setCount(0);
            } else {
                boolean.current = true;
                setCount(prev => prev + 1);
            }
        }, boolean.current === 0 ? 0 : 4000);

        return () => {
            clearInterval(timer);
        }
    }, [count]);

    const BannerEffect = {
        display: "flex",
        flexDirection: "row",
        alignItems: "center",
    }

    return (
        <>
            <Desktop>
                <div style={{
                    marginTop: "0.7em",
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center"
                }}>
                    <div className="ad_banner">
                        <div className="banner_list" count={count} boolean={boolean.current}
                            style={BannerEffect}>
                            <img src={process.env.PUBLIC_URL + "/image_src/" + bannerImgArray[count]}
                                style={{
                                    width: "63em",
                                    height: "5.8em",
                                    cursor: "pointer",
                                    alignItems: "center",
                                }}
                                onClick={() => {
                                    { boolean.current ? window.open("https://playdata.io/bootcamp-all", "_blank") : window.open("https://github.com/Domlnick/FinalProject", "_blank") }
                                }} />
                        </div>
                    </div>
                </div>
            </Desktop>
            <Tablet>
                <div style={{
                    marginTop: "2em",
                    display: "flex",
                    justifyContent: "center",
                }}>
                    <div className="ad_banner">
                        <div className="banner_list" count={count} boolean={boolean.current}
                            style={BannerEffect}>
                            <img src={process.env.PUBLIC_URL + "/image_src/" + bannerImgArray[count]}
                                style={{
                                    width: "40em",
                                    height: "5.5em",
                                    cursor: "pointer",
                                    alignItems: "center",
                                }}
                                onClick={() => {
                                    { boolean.current ? window.open("https://playdata.io/bootcamp-all", "_blank") : window.open("https://github.com/Domlnick/FinalProject", "_blank") }
                                }} />
                        </div>
                    </div>
                </div>
            </Tablet>
            <Mobile>
                <div style={{
                    marginTop: "-6vh",
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center"
                }}>
                    <div className="ad_banner">
                        <div className="banner_list" count={count} boolean={boolean.current}
                            style={BannerEffect}>
                            <img src={process.env.PUBLIC_URL + "/image_src/" + bannerImgArray[count]}
                                style={{
                                    width: "30em",
                                    height: "5.5em",
                                    cursor: "pointer",
                                    alignItems: "center",
                                }}
                                onClick={() => {
                                    { boolean.current ? window.open("https://playdata.io/bootcamp-all", "_blank") : window.open("https://github.com/Domlnick/FinalProject", "_blank") }
                                }} />
                        </div>
                    </div>
                </div>
            </Mobile>
        </>
    );
}


export { UploadArea, Banner };