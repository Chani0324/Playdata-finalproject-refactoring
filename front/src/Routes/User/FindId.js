import { Link, useNavigate } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import { Header } from "../../Components/Header";
import { useMediaQuery } from "react-responsive";
import NoPage from '../ErrorPage.js';
import axios from "axios";


const Desktop = ({ children }) => {
    const isDesktop = useMediaQuery({ minWidth: 1025 })
    return isDesktop ? children : null
};

const Tablet = ({ children }) => {
    const isTablet = useMediaQuery({ minWidth: 706, maxWidth: 1024 })
    return isTablet ? children : null
};

const Mobile = ({ children }) => {
    const isMobile = useMediaQuery({ maxWidth: 705 })
    return isMobile ? children : null
};

// 아이디 찾기 컴포넌트
function FindId() {

    const [userName, setUserName] = useState('');
    const [userEmail, setUserEmail] = useState('');
    const [disable, setDisable] = useState(true);
    const [opacity, setOpacity] = useState(0.5);

    const navigate = useNavigate();
    const goToShowIdPage = () => {
        if (userName.length >= 1 && userEmail.length >= 1) {
            navigate('/showid');
        }
    };

    useEffect(() => {
        handleDisable();
    });

    const handleInput = event => {
        return event.target.value;
    };

    const handleDisable = () => {
        userName && userEmail ? setOpacity(1) : setOpacity(0.5);
        userName && userEmail ? setDisable(false) : setDisable(true);
    };

    return (
        <>
            <Desktop>
                <Header />
                <div className="user-bg">
                    <div className="user-bg-rectangle">
                        <div className="user-bg-title">
                            <Link to="/">
                                <img src="/logos/title.png" width='60%' />
                            </Link>
                        </div>
                    </div>
                    <div className="findid-rectangle">

                        <img src="/logos/findid_logo.png" width='20%' className="findid-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="findid-title-img" />
                        <h5 className="findid-input-name-text">이름을 입력해주세요</h5>
                        <input type='text' className="findid-input-name" placeholder="Enter your name" value={userName} onChange={(event) => {
                            setUserName(handleInput(event));
                            handleDisable();
                        }} />
                        <h5 className="findid-input-email-text">이메일을 입력해주세요.</h5>
                        <input type="email" className="findid-input-email" placeholder="Enter your e-mail" value={userEmail} onChange={(event) => {
                            setUserEmail(handleInput(event));
                            handleDisable();
                        }} />
                        <div>
                            <button className="findid-button" disable={disable} style={{ opacity: opacity }} onClick={() => {
                                axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/findUserIdByEmailAndUsername', {
                                    params: {
                                        userName: userName,
                                        userEmail: userEmail
                                    }
                                }).then(function (response) {
                                    sessionStorage.setItem("foundUserId", response.data.result);
                                    sessionStorage.setItem('userEmail', userEmail);
                                    goToShowIdPage();
                                }).catch(function (error) {
                                    console.error(error);
                                })
                            }}>아이디 찾기</button>
                        </div>
                        <div className="find-pw">
                            <Link to='/FindPw'>비밀번호를 잊어버렸어요.</Link>
                        </div>

                    </div>
                </div>
            </Desktop>
            <Tablet>
                <Header />
                <div className="user-bg">
                    <div className="user-bg-rectangle-tablet">
                        <div className="user-bg-title-tablet">
                            <Link to="/">
                                <img src="/logos/title.png" width='60%' />
                            </Link>
                        </div>
                    </div>
                    <div className="findid-rectangle-tablet">
                        <img src="/logos/findid_logo.png" width='20%' className="findid-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="findid-title-img" />
                        <h5 className="findid-input-name-text">이름을 입력해주세요</h5>
                        <input type='text' className="findid-input-name" placeholder="Enter your name" value={userName} onChange={(event) => {
                            setUserName(handleInput(event));
                            handleDisable();
                        }} />
                        <h5 className="findid-input-email-text">이메일을 입력해주세요.</h5>
                        <input type='text' className="findid-input-email" placeholder="Enter your e-mail" value={userEmail} onChange={(event) => {
                            setUserEmail(handleInput(event));
                            handleDisable();
                        }} />
                        <div>
                            <button className="findid-button" disable={disable} style={{ opacity: opacity }} onClick={() => {
                                axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/findUserIdByEmailAndUsername', {
                                    params: {
                                        userName: userName,
                                        userEmail: userEmail
                                    }
                                }).then(function (response) {
                                    sessionStorage.setItem("foundUserId", response.data.result);
                                    sessionStorage.setItem('userEmail', userEmail);
                                    goToShowIdPage();
                                }).catch(function (error) {
                                    console.error(error);
                                })
                            }}>아이디 찾기</button>
                        </div>
                        <div className="find-pw">
                            <Link to='/FindPw'>비밀번호를 잊어버렸어요.</Link>
                        </div>
                    </div>
                </div>
            </Tablet>
            <Mobile>
                <Header />
                <div className="user-bg-mobile">
                    <div className="findid-rectangle-mobile">
                        <img src="/logos/findid_logo.png" width='20%' className="findid-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="findid-title-img" />
                        <h5 className="findid-input-name-text">이름을 입력해주세요</h5>
                        <input type='text' className="findid-input-name" placeholder="Enter your name" value={userName} onChange={(event) => {
                            setUserName(handleInput(event));
                            handleDisable();
                        }} />
                        <h5 className="findid-input-email-text">이메일을 입력해주세요.</h5>
                        <input type='text' className="findid-input-email" placeholder="Enter your e-mail" value={userEmail} onChange={(event) => {
                            setUserEmail(handleInput(event));
                            handleDisable();
                        }} />
                        <div>
                            <button className="findid-button" disable={disable} style={{ opacity: opacity }} onClick={() => {

                                axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/sendcodeid', {
                                    params: {
                                        userName: userName,
                                        userEmail: userEmail
                                    }
                                }).then(function (response) {
                                    sessionStorage.setItem("foundUserId", response.data.result);
                                    sessionStorage.setItem('userEmail', userEmail);
                                    goToShowIdPage();
                                }).catch(function (error) {
                                    console.error(error);
                                })
                            }}>아이디 찾기</button>
                        </div>
                        <div className="find-pw">
                            <Link to='/FindPw'>비밀번호를 잊어버렸어요.</Link>
                        </div>
                    </div>
                </div>
            </Mobile>
        </>
    )
};

// 찾은 아이디 결과 컴포넌트
function ShowId() {
    let isMemberText = "";
    let maskedId = "";
    const foundUserId = sessionStorage.getItem("foundUserId");
    let noMaskedId = "고객님의 아이디 : " + foundUserId;

    if (foundUserId != null) {
        if (foundUserId.length < 8) {
            maskedId = foundUserId.substring(0, 4) + foundUserId.substring(0, foundUserId.length - 4).replace(/[0-9a-zA-Z]/g, "*");
        }
    }

    if (sessionStorage.getItem("foundUserId") != "") {
        isMemberText += "고객님의 아이디 : " + maskedId;
    } else {
        isMemberText += "존재하지 않는 회원입니다.";
    }

    let matchCode = "";
    const [isMaskOn, setIsMaskOn] = useState(true);
    const [showGetCodeBtn, setShowGetCodeBtn] = useState(false);
    const [authCode, setAuthCode] = useState();
    const [userCode, setUserCode] = useState('');
    const [disable, setDisable] = useState(true);
    const [opacity, setOpacity] = useState(0.5);
    const [showAuthTag, setShowAuthTag] = useState(false);

    const handleDisable = () => {
        userCode.length >= 1 ? setOpacity(1) : setOpacity(0.5);
        userCode.length >= 1 ? setDisable(false) : setDisable(true);
    };

    const handleSubmit = event => {
        event.preventDefault();
        setUserCode('');
    };

    useEffect(() => {
        //언마운트 시 세션스토리지 foundUserId 삭제
        return() => {
            if(window.location.href != "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:3000/showid"){
                sessionStorage.removeItem("foundUserId");
                sessionStorage.removeItem("userEmail");
            }
        }
    }, [])

    useEffect(() => {
        matchCode = userCode;
    }, [userCode])

    const [isRunning, setIsRunning] = useState(false);

    const [minute, setMinute] = useState(0);
    const [second, setSecond] = useState(0);
    const [timerInterval, setTimerInterval] = useState(0);

    const tick = () => {
        if (second > 0) {
            setSecond((sec) => sec - 1);
        }

        if (second === 0) {
            if (minute === 0 && second < 2) {
                setIsRunning(false);
            } else {
                setMinute((min) => min - 1);
                setSecond(59);
            }
        }
    };

    const getTime = () => {
        setMinute(parseInt(299 / 60));
        setSecond(parseInt(299 % 60));
    }

    const customInterval = useInterval(() => {
        tick();
    }, isRunning ? 1000 : null);

    useEffect(() => {
        getTime();
    }, []);

    useEffect(() => {
        if (second === 0) {
            clearInterval(timerInterval);
        }
    }, [minute, second]);

    useEffect(() => {
        if (isRunning) {
            setTimerInterval(customInterval);
        }
    }, [isRunning]);

    useEffect(() => {
        setMinute(parseInt(299 / 60));
        setSecond(parseInt(299 % 60));
    }, [sessionStorage.getItem("authcode")])

    const timeFormat = () => {
        if (minute === 0) {
            return `   ${second}초`
        }
        return `${minute}분 ${second}초`
    }

    const navigateToLogin = useNavigate();
    const navigateToFindAgain = useNavigate();

    const goToLogin = () => {
        navigateToLogin('/login');
    };

    const goToFindAgain = () => {
        navigateToFindAgain('/findid')
    }
    if (sessionStorage.getItem("foundUserId") === null) {
        return (
            <>
                <NoPage />
            </>
        );
    } else {
        return (
            <>
                <Desktop>
                    <Header />
                    <div className="user-bg">
                        <div className="user-bg-rectangle">
                            <div className="user-bg-title">
                                <Link to="/">
                                    <img src="/logos/title.png" width='60%' />
                                </Link>
                            </div>
                        </div>
                        <div className="findid-rectangle">
                            <img src="/logos/findid_logo.png" width='20%' className="findid-logo-img" />
                            <img src="/logos/sub_title.png" width='50%' className="findid-title-img" />

                            <div>
                                {
                                    foundUserId.length === 0 ?
                                        <>
                                            <span className="findid-input-email-text">
                                                {isMemberText}
                                            </span>
                                            <button className="findid-button" onClick={() => {
                                                goToFindAgain();
                                            }}>아이디 다시 찾기</button>
                                        </> :
                                        <>
                                            <div style={{ marginTop: "20px", marginBottom: "30px" }}>
                                                <b className="findid-input-email-text">
                                                    {isMaskOn ? isMemberText : noMaskedId}
                                                </b>
                                                <button className="findid-button-getcode" disabled={showGetCodeBtn} onClick={() => {
                                                    axios({
                                                        method: "get",
                                                        url: "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/sendcodeid",
                                                        params: {
                                                            userId: foundUserId,
                                                            userEmail: sessionStorage.getItem('userEmail')
                                                        }
                                                    })
                                                        .then((res) => {
                                                            JSON.stringify(res.data);
                                                            if (res.data["authcode"].length >= 1) {
                                                                setAuthCode(res.data.authcode);
                                                                setShowAuthTag(true);
                                                                setMinute(parseInt(299 / 60));
                                                                setSecond(parseInt(299 % 60));
                                                                setIsRunning(true);
                                                            }
                                                        })
                                                        .catch((e) => {
                                                            console.error(e);
                                                        })
                                                }}>전체 확인</button>
                                            </div>
                                            {
                                                showAuthTag ?
                                                    <div>
                                                        <span style={{ fontWeight: "2", fontSize: "17px" }}>메일로 전송된 인증코드를 입력해주세요.</span>
                                                        <div style={{ marginTop: "20px" }}>
                                                            <form onSubmit={handleSubmit}>
                                                                {isRunning ? <p>남은시간 : {timeFormat()}</p> : <p style={{ color: "red" }}>시간초과 되었습니다. 다시 시도해주세요.</p>}

                                                                <input type="text" className="findid-input-getcode" onChange={(e) => {
                                                                    setUserCode(e.target.value);
                                                                    handleDisable();
                                                                }} />
                                                                <button type="submit" className="findid-button-getcode" disabled={!isRunning} style={{ marginLeft: "15px" }}
                                                                    // 인증코드 동일 여부 확인  
                                                                    onClick={() => {
                                                                        if (userCode == authCode) {
                                                                            setShowAuthTag(false);
                                                                            setDisable(true);
                                                                            setIsMaskOn(false);
                                                                            setShowGetCodeBtn(true);
                                                                        } else {
                                                                            alert("인증번호가 일치 하지 않습니다.");
                                                                        }
                                                                    }}
                                                                >확인</button>
                                                            </form>
                                                        </div>
                                                    </div> :
                                                    <></>
                                            }
                                            <button className="findid-button" onClick={() => {
                                                if (sessionStorage.getItem("foundUserId").length >= 1) {
                                                    sessionStorage.removeItem("foundUserId");
                                                }
                                                goToLogin();
                                            }}>로그인 하기</button>
                                        </>
                                }
                            </div>
                        </div>
                    </div>
                </Desktop>
                <Tablet>
                    <Header />
                    <div className="user-bg">
                        <div className="user-bg-rectangle-tablet">
                            <div className="user-bg-title-tablet">
                                <Link to="/">
                                    <img src="/logos/title.png" width='60%' />
                                </Link>
                            </div>
                        </div>

                        <div className="findid-rectangle-tablet">
                            <img src="/logos/findid_logo.png" width='20%' className="findid-logo-img" />
                            <img src="/logos/sub_title.png" width='50%' className="findid-title-img" />
                            <div>
                                {
                                    foundUserId.length === 0 ?
                                        <>
                                            <span className="findid-input-email-text">
                                                {isMemberText}
                                            </span>
                                            <button className="findid-button" onClick={() => {
                                                goToFindAgain();
                                            }}>아이디 다시 찾기</button>
                                        </> :
                                        <>
                                            <div style={{ marginTop: "20px", marginBottom: "30px" }}>
                                                <b className="findid-input-email-text">
                                                    {isMaskOn ? isMemberText : noMaskedId}
                                                </b>
                                                <button className="findid-button-getcode" disabled={showGetCodeBtn} onClick={() => {
                                                    // 이메일 전송 axios
                                                    axios({
                                                        method: "get",
                                                        url: "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/sendcodeid",
                                                        params: {
                                                            userId: foundUserId,
                                                            userEmail: sessionStorage.getItem('userEmail')
                                                        }
                                                    })
                                                        .then((res) => {
                                                            JSON.stringify(res.data);
                                                            if (res.data["authcode"].length >= 1) {
                                                                sessionStorage.setItem('authcode', res.data.authcode);
                                                                setShowAuthTag(true);
                                                                setMinute(parseInt(299 / 60));
                                                                setSecond(parseInt(299 % 60));
                                                                setIsRunning(true);
                                                            }
                                                        })
                                                        .catch((e) => {
                                                            console.error(e);
                                                        })
                                                }}>전체 확인</button>
                                            </div>
                                            {
                                                showAuthTag ?
                                                    <div>
                                                        <span style={{ fontWeight: "2", fontSize: "17px" }}>메일로 전송된 인증코드를 입력해주세요.</span>
                                                        <div style={{ marginTop: "20px" }}>
                                                            <form onSubmit={handleSubmit}>
                                                                {isRunning ? <p>남은시간 : {timeFormat()}</p> : <p style={{ color: "red" }}>시간초과 되었습니다. 다시 시도해주세요.</p>}

                                                                <input className="findid-input-getcode" onChange={(e) => {
                                                                    setUserCode(e.target.value);
                                                                    handleDisable();
                                                                }} />
                                                                <button type="submit" className="findid-button-getcode" disabled={disable} style={{ opacity: opacity, marginLeft: "15px" }}
                                                                    // 인증코드 동일 여부 확인  
                                                                    onClick={() => {
                                                                        if (userCode == sessionStorage.getItem("authcode")) {
                                                                            setShowAuthTag(false);
                                                                            setDisable(true);
                                                                            setIsMaskOn(false);
                                                                            setShowGetCodeBtn(true);
                                                                        } else {
                                                                            alert("인증번호가 일치 하지 않습니다.");
                                                                        }
                                                                    }}
                                                                >확인</button>
                                                            </form>
                                                        </div>
                                                    </div> :
                                                    <></>
                                            }
                                            <button className="findid-button" onClick={() => {
                                                if (sessionStorage.getItem("foundUserId").length >= 1) {
                                                    sessionStorage.removeItem("foundUserId");
                                                }
                                                goToLogin();
                                            }}>로그인 하기</button>
                                        </>
                                }
                            </div>
                        </div>
                    </div>

                </Tablet>
                <Mobile>
                    <Header />
                    <div className="user-bg-mobile">
                        <div className="findid-rectangle-mobile">
                            <img src="/logos/findid_logo.png" width='20%' className="findid-logo-img" />
                            <img src="/logos/sub_title.png" width='50%' className="findid-title-img" />
                            <div>
                                {
                                    foundUserId.length === 0 ?
                                        <>
                                            <span className="findid-input-email-text">
                                                {isMemberText}
                                            </span>
                                            <button className="findid-button" onClick={() => {
                                                goToFindAgain();
                                            }}>아이디 다시 찾기</button>
                                        </> :
                                        <>
                                            <div style={{ marginTop: "20px", marginBottom: "30px" }}>
                                                <b className="findid-input-email-text">
                                                    {isMaskOn ? isMemberText : noMaskedId}
                                                </b>
                                                <button className="findid-button-getcode" disabled={showGetCodeBtn} onClick={() => {
                                                    // 이메일 전송 axios
                                                    axios({
                                                        method: "get",
                                                        url: "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/sendcodeid",
                                                        params: {
                                                            userId: foundUserId,
                                                            userEmail: sessionStorage.getItem('userEmail')
                                                        }
                                                    })
                                                        .then((res) => {
                                                            JSON.stringify(res.data);
                                                            if (res.data["authcode"].length >= 1) {
                                                                sessionStorage.setItem('authcode', res.data.authcode);
                                                                setShowAuthTag(true);
                                                                setMinute(parseInt(299 / 60));
                                                                setSecond(parseInt(299 % 60));
                                                                setIsRunning(true);
                                                            }
                                                        })
                                                        .catch((e) => {
                                                            console.error(e);
                                                        })
                                                }}>전체 확인</button>
                                            </div>
                                            {
                                                showAuthTag ?
                                                    <div>
                                                        <span style={{ fontWeight: "2", fontSize: "17px" }}>메일로 전송된 인증코드를 입력해주세요.</span>
                                                        <div style={{ marginTop: "20px" }}>
                                                            <form onSubmit={handleSubmit}>
                                                                {isRunning ? <p>남은시간 : {timeFormat()}</p> : <p style={{ color: "red" }}>시간초과 되었습니다. 다시 시도해주세요.</p>}

                                                                <input className="findid-input-getcode" onChange={(e) => {
                                                                    setUserCode(e.target.value);
                                                                    handleDisable();
                                                                }} />
                                                                <button type="submit" className="findid-button-getcode" disabled={isRunning ? disable : !disable} style={{ opacity: opacity, marginLeft: "15px" }}
                                                                    // 인증코드 동일 여부 확인  
                                                                    onClick={() => {
                                                                        if (userCode == sessionStorage.getItem("authcode")) {
                                                                            setShowAuthTag(false);
                                                                            setDisable(true);
                                                                            setIsMaskOn(false);
                                                                            setShowGetCodeBtn(true);
                                                                        } else {
                                                                            alert("인증번호가 일치 하지 않습니다.");
                                                                        }
                                                                    }}
                                                                >확인</button>
                                                            </form>
                                                        </div>
                                                    </div> :
                                                    <></>
                                            }
                                            <button className="findid-button" onClick={() => {
                                                if (sessionStorage.getItem("foundUserId").length >= 1) {
                                                    sessionStorage.removeItem("foundUserId");
                                                }
                                                goToLogin();
                                            }}>로그인 하기</button>
                                        </>
                                }
                            </div>
                        </div>
                    </div>
                </Mobile>
            </>
        )
    }
};

function useInterval(callback, delay) {
    const savedCallback = useRef();

    // Remember the latest callback.
    useEffect(() => {
        savedCallback.current = callback;
    }, [callback]);

    // Set up the interval.
    useEffect(() => {
        function tick() {
            savedCallback.current();
        }
        if (delay !== null) {
            let id = setInterval(tick, delay);
            return () => clearInterval(id);
        }
    }, [delay]);
}

export { FindId, ShowId };