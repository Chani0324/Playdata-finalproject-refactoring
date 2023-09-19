import { Link, useNavigate } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import { Header } from "../../Components/Header";
import { useMediaQuery } from "react-responsive";
import Cookies from "universal-cookie";
import axios from "axios";
import { logout } from "./Login";


const cookies = new Cookies();

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

// 비밀번호 찾기 컴포넌트
function FindPw() {
    const [userName, setName] = useState('');
    const [userId, setUserId] = useState('');
    const [userEmail, setUserEmail] = useState('');
    const [disable, setDisable] = useState(true);
    const [disableCodeBtn, setDisableCodeBtn] = useState(true);
    const [disableCodeInput, setDisableCodeInput] = useState(false);
    const [opacity, setOpacity] = useState(0.5);
    const [isSameCode, setIsSameCode] = useState(false);
    const [isExistUser, setIsExistUser] = useState(true);
    const [isShow, setIsShow] = useState(true);
    const [authCode, setAuthCode] = useState(null);
    const navigate = useNavigate();

    const goToResetPw = () => {
        navigate('/resetpw');
    };

    useEffect(() => {
        handleDisable();
    });

    const handleInput = event => {
        return event.target.value;
    };

    const isValidEmail = userEmail.includes('@') && userEmail.includes('.');

    const handleDisable = () => {
        userName && userId && isValidEmail ? setOpacity(1) : setOpacity(0.5);
        userName && userId && isValidEmail ? setDisable(false) : setDisable(true);
    };

    const handleDisableGetCode = () => {
        userName && userId && isValidEmail ? setOpacity(1) : setOpacity(0.5);
        userName && userId && isValidEmail ? setDisableCodeBtn(false) : setDisableCodeBtn(true);
    };

    let matchCode = "";
    const [isRunning, setIsRunning] = useState(false);
    const [userCode, setUserCode] = useState('');
    const [showAuthTag, setShowAuthTag] = useState(false);
    const [minute, setMinute] = useState(0);
    const [second, setSecond] = useState(0);
    const [timerInterval, setTimerInterval] = useState(0);

    const handleSubmit = event => {
        event.preventDefault();
        setUserCode('');

        console.log(matchCode);
    };

    useEffect(() => {
        matchCode = userCode;
    }, [userCode])

    const tick = () => {
        if (second > 0) {
            setSecond((sec) => sec - 1);
        }

        if (second === 0) {
            if (minute === 0) {
                setIsRunning(false);
                sessionStorage.removeItem("authcode");
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
    }, [])

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

    if (!isExistUser) {
        sessionStorage.removeItem("userId");
        sessionStorage.removeItem("userEmail");
    }

    useEffect(() => {
        return () => {
            if (window.location.href != "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:3000/resetpw") {
                sessionStorage.removeItem("userId");
                sessionStorage.removeItem("userEmail");
            }
        }
    }, [])

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
                    <div className="findpw-rectangle">
                        <img src="/logos/findpw_logo.png" width='30%' className="findpw-logo-img" />
                        <div></div>
                        <img src="/logos/sub_title.png" width='50%' className="findpw-title-img" />
                        <form onSubmit={handleSubmit}>
                            <h5 className="findpw-input-name-text">이름을 입력해주세요</h5>
                            <input type='text' className="findpw-input-name" placeholder="Enter your name" value={userName} onChange={(event) => {
                                setName(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="findpw-input-id-text">아이디를 입력해주세요.</h5>
                            <input type='text' className="findpw-input-id" placeholder="Enter your I'd" value={userId} onChange={(event) => {
                                setUserId(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="findpw-input-email-text">이메일을 입력해주세요.</h5>
                            <span style={{ position: "relative" }}>
                                <input type='email' className="findpw-input-email" placeholder="Enter your e-mail" value={userEmail} style={{ marginLeft: "-50px", width: "250px" }} onChange={(event) => {
                                    setUserEmail(handleInput(event));
                                    handleDisableGetCode();
                                }} />

                                <button disabled={disableCodeBtn} style={{ position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" }}
                                    onClick={() => {
                                        if (isValidEmail) {
                                            axios({
                                                method: "get",
                                                url: "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/sendcodepw",
                                                params: {
                                                    userId: userId,
                                                    userName: userName,
                                                    userEmail: userEmail
                                                }
                                            }).then((res) => {
                                                JSON.stringify(res.data);
                                                if (res.data.result === "true") {
                                                    setIsExistUser(true);
                                                    sessionStorage.setItem("userId", userId);
                                                    sessionStorage.setItem("userName", userName);
                                                    sessionStorage.setItem("userEmail", userEmail);
                                                    if (res.data["authcode"].length >= 1) {
                                                        setAuthCode(res.data.authcode);
                                                        setShowAuthTag(true);
                                                        setMinute(parseInt(299 / 60));
                                                        setSecond(parseInt(299 % 60));
                                                        setIsRunning(true);
                                                    }
                                                } else if (res.data.result === "false") {
                                                    setDisable(false);
                                                    setIsExistUser(false);
                                                }
                                            }).catch((e) => {
                                                console.error(e);
                                            })
                                        } else if (!isValidEmail) {
                                            alert("이메일 형식이 잘못되었습니다.");
                                        }
                                    }}>인증</button>
                            </span>
                            {isExistUser ? <></> : <p style={{ marginTop: "15px", fontSize: "17px", color: "red" }}>회원정보가 존재하지 않습니다.</p>}
                            {
                                showAuthTag ?
                                    <>
                                        <h5 className="findpw-input-cn-text">메일로 발송된 인증번호를 입력해주세요.</h5>
                                        {!isSameCode ? <p style={{ fontSize: "15px", marginBottom: "5px" }}>남은시간 : {timeFormat()}</p> : <p style={{ color: "red", fontSize: "17px", marginBottom: "5px" }}>시간초과 되었습니다. 다시 시도해주세요.</p>}
                                        <input type='text' className="findpw-input-cn" disabled={disableCodeInput} placeholder="Enter your code" style={{ marginLeft: "-50px", width: "250px" }} onChange={(event) => {
                                            setUserCode(event.target.value);
                                            handleDisable();
                                        }} />
                                        <button disabled={disableCodeBtn} style={isShow ? { position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" } : { display: "none", position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" }}
                                            // 인증코드 동일 여부 확인  
                                            onClick={() => {
                                                console.log("비교시점: " + authCode);
                                                if (userCode == authCode) {
                                                    setDisableCodeInput(true);
                                                    setDisableCodeBtn(true);
                                                    setIsShow(false);
                                                    sessionStorage.removeItem("authcode")
                                                } else {
                                                    alert("인증번호가 일치 하지 않습니다.");
                                                }
                                            }}
                                        >인증완료</button>
                                        <img src={process.env.PUBLIC_URL + "image_src/check.png"}
                                            style={isShow ? { display: "none", width: "20px", position: "absolute", margin: "5px 0 0 13px" } : { width: "28px", position: "absolute", margin: "5px 0 0 13px" }}
                                        />

                                    </> :
                                    <></>
                            }
                        </form>
                        <div>
                            <button className="findpw-button" disabled={disable} style={{ opacity: opacity }} onClick={() => {
                                // Ajax를 통한 서버 연동 후 새로운 패스워드 입력 페이지로 이동.
                                if (sessionStorage.getItem("userId") != null && sessionStorage.getItem("userName") && sessionStorage.getItem("userEmail") != null && (sessionStorage.getItem("authcode") == null)) {
                                    goToResetPw();
                                }
                            }}>비밀번호 찾기</button>
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
                    <div className="findpw-rectangle">
                        <img src="/logos/findpw_logo.png" width='30%' className="findpw-logo-img" />
                        <div></div>
                        <img src="/logos/sub_title.png" width='50%' className="findpw-title-img" />
                        <form onSubmit={handleSubmit}>
                            <h5 className="findpw-input-name-text">이름을 입력해주세요</h5>
                            <input type='text' className="findpw-input-name" placeholder="Enter your name" value={userName} onChange={(event) => {
                                setName(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="findpw-input-id-text">아이디를 입력해주세요.</h5>
                            <input type='text' className="findpw-input-id" placeholder="Enter your I'd" value={userId} onChange={(event) => {
                                setUserId(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="findpw-input-email-text">이메일을 입력해주세요.</h5>
                            <span style={{ position: "relative" }}>
                                <input type='email' className="findpw-input-email" placeholder="Enter your e-mail" value={userEmail} style={{ marginLeft: "-50px", width: "250px" }} onChange={(event) => {
                                    setUserEmail(handleInput(event));
                                    handleDisableGetCode();
                                }} />

                                {
                                    isRunning ?
                                        <></> :
                                        <button disabled={disableCodeBtn} style={{ position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" }}
                                            onClick={() => {
                                                if (isValidEmail) {
                                                    axios({
                                                        method: "get",
                                                        url: "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/sendcodepw",
                                                        params: {
                                                            userId: userId,
                                                            userName: userName,
                                                            userEmail: userEmail
                                                        }
                                                    }).then((res) => {
                                                        JSON.stringify(res.data);
                                                        if (res.data.result === "true") {
                                                            setIsExistUser(true);
                                                            sessionStorage.setItem("userId", userId);
                                                            sessionStorage.setItem("userName", userName);
                                                            sessionStorage.setItem("userEmail", userEmail);
                                                            if (res.data["authcode"].length >= 1) {
                                                                setAuthCode(res.data.authcode);
                                                                setShowAuthTag(true);
                                                                setMinute(parseInt(299 / 60));
                                                                setSecond(parseInt(299 % 60));
                                                                setIsRunning(true);
                                                            }
                                                        } else if (res.data.result === "false") {
                                                            setDisable(false);
                                                            setIsExistUser(false);
                                                        }
                                                    }).catch((e) => {
                                                        console.error(e);
                                                    })
                                                } else if (!isValidEmail) {
                                                    alert("이메일 형식이 잘못되었습니다.");
                                                }
                                            }}>인증</button>
                                }
                            </span>
                            {isExistUser ? <></> : <p style={{ marginTop: "15px", fontSize: "17px", color: "red" }}>회원정보가 존재하지 않습니다.</p>}
                            {
                                showAuthTag ?
                                    <>
                                        <h5 className="findpw-input-cn-text">메일로 발송된 인증번호를 입력해주세요.</h5>
                                        {!isSameCode ? <p style={{ fontSize: "15px", marginBottom: "5px" }}>남은시간 : {timeFormat()}</p> : <p style={{ color: "red", fontSize: "17px", marginBottom: "5px" }}>시간초과 되었습니다. 다시 시도해주세요.</p>}
                                        <input type='text' className="findpw-input-cn" disabled={disableCodeInput} placeholder="Enter your code" style={{ marginLeft: "-50px", width: "250px" }} onChange={(event) => {
                                            setUserCode(event.target.value);
                                            handleDisable();
                                        }} />
                                        <button disabled={disableCodeBtn} style={isShow ? { position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" } : { display: "none", position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" }}
                                            // 인증코드 동일 여부 확인  
                                            onClick={() => {
                                                if (userCode == sessionStorage.getItem("authcode")) {
                                                    setDisableCodeInput(true);
                                                    setIsShow(false);
                                                    sessionStorage.removeItem("authcode")
                                                } else {
                                                    alert("인증번호가 일치 하지 않습니다.");
                                                }
                                            }}
                                        >인증완료</button>
                                        <img src={process.env.PUBLIC_URL + "image_src/check.png"}
                                            style={isShow ? { display: "none", width: "20px", position: "absolute", margin: "5px 0 0 13px" } : { width: "28px", position: "absolute", margin: "5px 0 0 13px" }}
                                        />

                                    </> :
                                    <></>
                            }
                        </form>
                        <div>
                            <button className="findpw-button" disabled={disable} style={{ opacity: opacity }} onClick={() => {
                                // Ajax를 통한 서버 연동 후 새로운 패스워드 입력 페이지로 이동.
                                if (sessionStorage.getItem("userId") != null && sessionStorage.getItem("userName") && sessionStorage.getItem("userEmail") != null && (sessionStorage.getItem("authcode") == null)) {
                                    goToResetPw();
                                }
                            }}>비밀번호 찾기</button>
                        </div>
                    </div>
                </div>
            </Tablet>
            <Mobile>
                <Header />
                <div className="user-bg-mobile">
                    <div className="findpw-rectangle">
                        <img src="/logos/findpw_logo.png" width='30%' className="findpw-logo-img" />
                        <div></div>
                        <img src="/logos/sub_title.png" width='50%' className="findpw-title-img" />
                        <form onSubmit={handleSubmit}>
                            <h5 className="findpw-input-name-text">이름을 입력해주세요</h5>
                            <input type='text' className="findpw-input-name" placeholder="Enter your name" value={userName} onChange={(event) => {
                                setName(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="findpw-input-id-text">아이디를 입력해주세요.</h5>
                            <input type='text' className="findpw-input-id" placeholder="Enter your I'd" value={userId} onChange={(event) => {
                                setUserId(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="findpw-input-email-text">이메일을 입력해주세요.</h5>
                            <span style={{ position: "relative" }}>
                                <input type='email' className="findpw-input-email" placeholder="Enter your e-mail" value={userEmail} style={{ marginLeft: "-50px", width: "250px" }} onChange={(event) => {
                                    setUserEmail(handleInput(event));
                                    handleDisableGetCode();
                                }} />

                                {
                                    isRunning ?
                                        <></> :
                                        <button disabled={disableCodeBtn} style={{ position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" }}
                                            onClick={() => {
                                                if (isValidEmail) {
                                                    axios({
                                                        method: "get",
                                                        url: "http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/sendcodepw",
                                                        params: {
                                                            userId: userId,
                                                            userName: userName,
                                                            userEmail: userEmail
                                                        }
                                                    }).then((res) => {
                                                        JSON.stringify(res.data);
                                                        if (res.data.result === "true") {
                                                            setIsExistUser(true);
                                                            sessionStorage.setItem("userId", userId);
                                                            sessionStorage.setItem("userName", userName);
                                                            sessionStorage.setItem("userEmail", userEmail);
                                                            if (res.data["authcode"].length >= 1) {
                                                                setAuthCode(res.data.authcode);
                                                                setShowAuthTag(true);
                                                                setMinute(parseInt(299 / 60));
                                                                setSecond(parseInt(299 % 60));
                                                                setIsRunning(true);
                                                            }
                                                        } else if (res.data.result === "false") {
                                                            setDisable(false);
                                                            setIsExistUser(false);
                                                        }
                                                    }).catch((e) => {
                                                        console.error(e);
                                                    })
                                                } else if (!isValidEmail) {
                                                    alert("이메일 형식이 잘못되었습니다.");
                                                }
                                            }}>인증</button>
                                }
                            </span>
                            {isExistUser ? <></> : <p style={{ marginTop: "15px", fontSize: "17px", color: "red" }}>회원정보가 존재하지 않습니다.</p>}
                            {
                                showAuthTag ?
                                    <>
                                        <h5 className="findpw-input-cn-text">메일로 발송된 인증번호를 입력해주세요.</h5>
                                        {!isSameCode ? <p style={{ fontSize: "15px", marginBottom: "5px" }}>남은시간 : {timeFormat()}</p> : <p style={{ color: "red", fontSize: "17px", marginBottom: "5px" }}>시간초과 되었습니다. 다시 시도해주세요.</p>}
                                        <input type='text' className="findpw-input-cn" disabled={disableCodeInput} placeholder="Enter your code" style={{ marginLeft: "-50px", width: "250px" }} onChange={(event) => {
                                            setUserCode(event.target.value);
                                            handleDisable();
                                        }} />
                                        <button disabled={disableCodeBtn} style={isShow ? { position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" } : { display: "none", position: "absolute", width: "50px", height: "44px", fontSize: "4px", border: "1px solid #494949", borderRadius: "8px", boxSizing: "border-box" }}
                                            // 인증코드 동일 여부 확인  
                                            onClick={() => {
                                                if (userCode == sessionStorage.getItem("authcode")) {
                                                    setDisableCodeInput(true);
                                                    setIsShow(false);
                                                    sessionStorage.removeItem("authcode")
                                                } else {
                                                    alert("인증번호가 일치 하지 않습니다.");
                                                }
                                            }}
                                        >인증완료</button>
                                        <img src={process.env.PUBLIC_URL + "image_src/check.png"}
                                            style={isShow ? { display: "none", width: "20px", position: "absolute", margin: "5px 0 0 13px" } : { width: "28px", position: "absolute", margin: "5px 0 0 13px" }}
                                        />

                                    </> :
                                    <></>
                            }
                        </form>
                        <div>
                            <button className="findpw-button" disabled={disable} style={{ opacity: opacity }} onClick={() => {
                                // Ajax를 통한 서버 연동 후 새로운 패스워드 입력 페이지로 이동.
                                if (sessionStorage.getItem("userId") != null && sessionStorage.getItem("userName") && sessionStorage.getItem("userEmail") != null && (sessionStorage.getItem("authcode") == null)) {
                                    goToResetPw();
                                }
                            }}>비밀번호 찾기</button>
                        </div>
                    </div>
                </div>
            </Mobile>
        </>
    )
}

// 비밀번호 업데이트 컴포넌트
function ResetPw() {

    const cookies = new Cookies();

    const [password, setPassword] = useState('');
    const [passwordConfirm, setPasswordConfirm] = useState('');
    const [disable, setDisable] = useState(true);
    const [opacity, setOpacity] = useState(0.5);

    const [newPassword, setNewPassword] = useState('새로운 비밀번호를 입력해 주세요.')
    const [reNewPassword, setReNewPassword] = useState('한번 더 입력해 주세요.');

    const [newPasswordErrorColor, setNewPasswordErrorColor] = useState('#494949');
    const [reNewPasswordErrorColor, setReNewPasswordErrorColor] = useState('#494949');

    const navigate = useNavigate();
    const goToList = () => {
        navigate('/login');
    };

    const specialLetter = password.search(/[`~!@@#$%^&*|₩₩₩'₩";:₩/?]/gi);

    const isValidPassword = password.length >= 8 && specialLetter >= 1;

    const isValidPasswordConfirm = passwordConfirm === password;

    const handleDisable = () => {
        isValidPassword && isValidPasswordConfirm ? setDisable(false) : setDisable(true);
        isValidPassword && isValidPasswordConfirm ? setOpacity(1) : setOpacity(0.5);
    };

    const newPasswordErrorHandler = () => {
        if (!isValidPassword) {
            setNewPassword('특수문자를 포함한 8자 이상 입력해 주세요.');
            setNewPasswordErrorColor('red');
        } else {
            setNewPassword('정상입니다.');
            setNewPasswordErrorColor('blue');
        }
    };

    const reNewPasswordErrorHandler = () => {
        if (!isValidPasswordConfirm) {
            setReNewPassword('비밀번호가 일치하지않습니다.');
            setReNewPasswordErrorColor('red');
        } else {
            setReNewPassword('비밀번호가 일치합니다.');
            setReNewPasswordErrorColor('blue');
        }
    };

    useEffect(() => {
        if (password.length >= 1) {
            newPasswordErrorHandler();
        }
    }, [password]);

    useEffect(() => {
        if (passwordConfirm.length >= 1) {
            reNewPasswordErrorHandler();
        }
    }, [passwordConfirm]);

    useEffect(() => {
        handleDisable();
    });

    const handleInput = event => {
        return event.target.value;
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
                    <div className="resetpw-rectangle">
                        <img src="/logos/reset_pw_logo.png" width='40%' className="resetpw-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="resetpw-title-img" />
                        <h5 className="resetpw-input-pw-text" style={{ color: newPasswordErrorColor }}>{newPassword}</h5>
                        <input type='password' className="resetpw-input-pw" placeholder="Enter your new password" style={{ borderColor: newPasswordErrorColor }} value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            newPasswordErrorHandler();
                            handleDisable();
                        }} />
                        <h5 className="resetpw-re-input-pw-text" style={{ color: reNewPasswordErrorColor }}>{reNewPassword}</h5>
                        <input type='password' className="resetpw-re-input-pw" placeholder="Enter re-password" style={{ borderColor: reNewPasswordErrorColor }} value={passwordConfirm} onChange={(event) => {
                            setPasswordConfirm(handleInput(event));
                            reNewPasswordErrorHandler();
                            handleDisable();
                        }} />
                        <div>
                            <button className="resetpw-button" disabled={disable} style={{ opacity: opacity }}
                                onClick={() => {
                                    axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/updateuserpw', {
                                        userEmail: sessionStorage.getItem("userEmail"),
                                        userId: sessionStorage.getItem("userId"),
                                        password: password
                                    }).then(function (response) {
                                        sessionStorage.removeItem("userId")
                                        sessionStorage.removeItem("userEmail")

                                    }).catch(function (error) {
                                        console.error(error);
                                        console.log('에러가 발생되었습니다.')
                                    })
                                }}>완료</button>
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
                    <div className="resetpw-rectangle-tablet">
                        <img src="/logos/reset_pw_logo.png" width='40%' className="resetpw-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="resetpw-title-img" />
                        <h5 className="resetpw-input-pw-text" style={{ color: newPasswordErrorColor }}>{newPassword}</h5>
                        <input type='password' className="resetpw-input-pw" placeholder="Enter your new password" style={{ borderColor: newPasswordErrorColor }} value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            handleDisable();
                            newPasswordErrorHandler();
                        }} />
                        <h5 className="resetpw-re-input-pw-text" style={{ color: reNewPasswordErrorColor }}>{reNewPassword}</h5>
                        <input type='password' className="resetpw-re-input-pw" placeholder="Enter re-password" style={{ borderColor: reNewPasswordErrorColor }} value={passwordConfirm} onChange={(event) => {
                            setPasswordConfirm(handleInput(event));
                            handleDisable();
                            reNewPasswordErrorHandler();
                        }} />
                        <div>
                            <button className="resetpw-button" disabled={disable} style={{ opacity: opacity }}
                                onClick={() => {
                                    axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/updateuserpw', {
                                        userEmail: sessionStorage.getItem("userEmail"),
                                        userId: sessionStorage.getItem("userId"),
                                        password: password
                                    }).then(function (response) {
                                        sessionStorage.removeItem("userId")
                                        sessionStorage.removeItem("userEmail")

                                    }).catch(function (error) {
                                        console.error(error);
                                        console.log('에러가 발생되었습니다.')
                                    })
                                }}>완료</button>
                        </div>
                    </div>
                </div>
            </Tablet>

            <Mobile>
                <Header />
                <div className="user-bg-mobile">
                    <div className="resetpw-rectangle-mobile">
                        <img src="/logos/reset_pw_logo.png" width='50%' className="resetpw-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="resetpw-title-img" />
                        <h5 className="resetpw-input-pw-text" style={{ color: newPasswordErrorColor }}>{newPassword}</h5>
                        <input type='password' className="resetpw-input-pw" placeholder="Enter your new password" style={{ borderColor: newPasswordErrorColor }} value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            handleDisable();
                            newPasswordErrorHandler();
                        }} />
                        <h5 className="resetpw-re-input-pw-text" style={{ color: reNewPasswordErrorColor }}>{reNewPassword}</h5>
                        <input type='password' className="resetpw-re-input-pw" placeholder="Enter re-password" style={{ borderColor: reNewPasswordErrorColor }} value={passwordConfirm} onChange={(event) => {
                            setPasswordConfirm(handleInput(event));
                            handleDisable();
                            reNewPasswordErrorHandler();
                        }} />
                        <div>
                            <button className="resetpw-button" disabled={disable} style={{ opacity: opacity }}
                                onClick={() => {
                                    axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/updateuserpw', {
                                        userEmail: sessionStorage.getItem("userEmail"),
                                        userId: sessionStorage.getItem("userId"),
                                        password: password
                                    }).then(function (response) {
                                        sessionStorage.removeItem("userId")
                                        sessionStorage.removeItem("userEmail")

                                    }).catch(function (error) {
                                        console.error(error);
                                        console.log('에러가 발생되었습니다.')
                                    })
                                }}>완료</button>
                        </div>
                    </div>
                </div>
            </Mobile>
        </>
    )
}

// 로그인 유저 비밀번호 업데이트 컴포넌트
function LoginResetPw() {

    const [password, setPassword] = useState('');
    const [passwordConfirm, setPasswordConfirm] = useState('');
    const [disable, setDisable] = useState(true);
    const [opacity, setOpacity] = useState(0.5);

    const [newPassword, setNewPassword] = useState('새로운 비밀번호를 입력해 주세요.')
    const [reNewPassword, setReNewPassword] = useState('한번 더 입력해 주세요.');

    const [newPasswordErrorColor, setNewPasswordErrorColor] = useState('#494949');
    const [reNewPasswordErrorColor, setReNewPasswordErrorColor] = useState('#494949');

    const navigate = useNavigate();
    const goToList = () => {
        navigate('/login');
    };

    const specialLetter = password.search(/[`~!@@#$%^&*|₩₩₩'₩";:₩/?]/gi);

    const isValidPassword = password.length >= 8 && specialLetter >= 1;

    const isValidPasswordConfirm = passwordConfirm === password;

    const handleDisable = () => {
        isValidPassword && isValidPasswordConfirm ? setDisable(false) : setDisable(true);
        isValidPassword && isValidPasswordConfirm ? setOpacity(1) : setOpacity(0.5);
    };

    const newPasswordErrorHandler = () => {
        if (!isValidPassword) {
            setNewPassword('특수문자를 포함한 8자 이상 입력해 주세요.');
            setNewPasswordErrorColor('red');
        } else {
            setNewPassword('정상입니다.');
            setNewPasswordErrorColor('blue');
        }
    };

    const reNewPasswordErrorHandler = () => {
        if (!isValidPasswordConfirm) {
            setReNewPassword('비밀번호가 일치하지않습니다.');
            setReNewPasswordErrorColor('red');
        } else {
            setReNewPassword('비밀번호가 일치합니다.');
            setReNewPasswordErrorColor('blue');
        }
    };

    useEffect(() => {
        if (password.length >= 1) {
            newPasswordErrorHandler();
        }
    }, [password]);

    useEffect(() => {
        if (passwordConfirm.length >= 1) {
            reNewPasswordErrorHandler();
        }
    }, [passwordConfirm]);

    useEffect(() => {
        handleDisable();
    });

    const handleInput = event => {
        return event.target.value;
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
                    <div className="resetpw-rectangle">
                        <img src="/logos/reset_pw_logo.png" width='40%' className="resetpw-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="resetpw-title-img" />
                        <h5 className="resetpw-input-pw-text" style={{ color: newPasswordErrorColor }}>{newPassword}</h5>
                        <input type='password' className="resetpw-input-pw" placeholder="Enter your new password" style={{ borderColor: newPasswordErrorColor }} value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            newPasswordErrorHandler();
                            handleDisable();
                        }} />
                        <h5 className="resetpw-re-input-pw-text" style={{ color: reNewPasswordErrorColor }}>{reNewPassword}</h5>
                        <input type='password' className="resetpw-re-input-pw" placeholder="Enter re-password" style={{ borderColor: reNewPasswordErrorColor }} value={passwordConfirm} onChange={(event) => {
                            setPasswordConfirm(handleInput(event));
                            reNewPasswordErrorHandler();
                            handleDisable();
                        }} />
                        <div>
                            <button className="resetpw-button" disabled={disable} style={{ opacity: opacity }}
                                onClick={() => {
                                    axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/updatelogineduserpw', {
                                        password: password
                                    },
                                        {
                                            headers: {
                                                Authorization: cookies.get('accessToken')
                                            }
                                        }).then(function (respons) {
                                            console.log(respons);
                                            if (respons.data.result == 'true') {
                                                logout();
                                                alert('비밀번호가 변경되었습니다. 다시 로그인 해주세요.');
                                                goToList();
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                            console.log('에러가 발생되었습니다.')
                                        })
                                }}>완료</button>
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
                    <div className="resetpw-rectangle-tablet">
                        <img src="/logos/reset_pw_logo.png" width='40%' className="resetpw-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="resetpw-title-img" />
                        <h5 className="resetpw-input-pw-text" style={{ color: newPasswordErrorColor }}>{newPassword}</h5>
                        <input type='password' className="resetpw-input-pw" placeholder="Enter your new password" style={{ borderColor: newPasswordErrorColor }} value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            handleDisable();
                            newPasswordErrorHandler();
                        }} />
                        <h5 className="resetpw-re-input-pw-text" style={{ color: reNewPasswordErrorColor }}>{reNewPassword}</h5>
                        <input type='password' className="resetpw-re-input-pw" placeholder="Enter re-password" style={{ borderColor: reNewPasswordErrorColor }} value={passwordConfirm} onChange={(event) => {
                            setPasswordConfirm(handleInput(event));
                            handleDisable();
                            reNewPasswordErrorHandler();
                        }} />
                        <div>
                            <button className="resetpw-button" disabled={disable} style={{ opacity: opacity }}
                                onClick={() => {
                                    axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/updatelogineduserpw', {
                                        password: password
                                    },
                                        {
                                            headers: {
                                                Authorization: cookies.get('accessToken')
                                            }
                                        }).then(function (respons) {
                                            console.log(respons);
                                            if (respons.data.result == 'true') {
                                                logout();
                                                alert('비밀번호가 변경되었습니다. 다시 로그인 해주세요.');
                                                goToList();
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                            console.log('에러가 발생되었습니다.')
                                        })
                                }}>완료</button>
                        </div>
                    </div>
                </div>
            </Tablet>

            <Mobile>
                <Header />
                <div className="user-bg-mobile">
                    <div className="resetpw-rectangle-mobile">
                        <img src="/logos/reset_pw_logo.png" width='50%' className="resetpw-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="resetpw-title-img" />
                        <h5 className="resetpw-input-pw-text" style={{ color: newPasswordErrorColor }}>{newPassword}</h5>
                        <input type='password' className="resetpw-input-pw" placeholder="Enter your new password" style={{ borderColor: newPasswordErrorColor }} value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            handleDisable();
                            newPasswordErrorHandler();
                        }} />
                        <h5 className="resetpw-re-input-pw-text" style={{ color: reNewPasswordErrorColor }}>{reNewPassword}</h5>
                        <input type='password' className="resetpw-re-input-pw" placeholder="Enter re-password" style={{ borderColor: reNewPasswordErrorColor }} value={passwordConfirm} onChange={(event) => {
                            setPasswordConfirm(handleInput(event));
                            handleDisable();
                            reNewPasswordErrorHandler();
                        }} />
                        <div>
                            <button className="resetpw-button" disabled={disable} style={{ opacity: opacity }}
                                onClick={() => {
                                    axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/updatelogineduserpw', {
                                        password: password
                                    },
                                        {
                                            headers: {
                                                Authorization: cookies.get('accessToken')
                                            }
                                        }).then(function (respons) {
                                            console.log(respons);
                                            if (respons.data.result == 'true') {
                                                logout();
                                                alert('비밀번호가 변경되었습니다. 다시 로그인 해주세요.');
                                                goToList();
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                            console.log('에러가 발생되었습니다.')
                                        })
                                }}>완료</button>
                        </div>
                    </div>
                </div>
            </Mobile>
        </>
    )
}

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

export { FindPw, ResetPw, LoginResetPw };