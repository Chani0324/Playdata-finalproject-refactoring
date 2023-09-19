import { Link, useNavigate } from "react-router-dom";
import { useState, useEffect } from "react";
import { Header } from "../../Components/Header";
import { useMediaQuery } from "react-responsive";
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

// 회원가입 컴포넌트
function Register() {

    const [userName, setUserName] = useState('');
    const [userEmail, setUserEmail] = useState('');
    const [userId, setUserId] = useState('');
    const [password, setPassword] = useState('');
    const [passwordConfirm, setPasswordConfirm] = useState('');

    const [disable, setDisable] = useState(true);
    const [opacity, setOpacity] = useState(0.5);

    // input Error 메세지
    const [showNameErrorMessage, setUserNameShowErrorMessage] = useState('이름을 입력해 주세요.');
    const [showEmailErrorMessage, setUserEmailShowErrorMessage] = useState('이메일을 입력해 주세요.');
    const [showIdErrorMessage, setUserIdShowErrorMessage] = useState('아이디를 입력해 주세요.');
    const [showPwErrorMessage, setPwShowErrorMessage] = useState('비밀번호를 입력해 주세요.');
    const [showRePwErrorMessage, setRePwShowErrorMessage] = useState('비밀번호를 한번 더 입력해주세요.');

    // input Error border color
    const [userNameErrorBorderColor, setUserNameErrorBorderColor] = useState('#494949');
    const [userEmailErrorBorderColor, setUserEmailErrorBorderColor] = useState('#494949');
    const [userIdErrorBorderColor, setUserIdErrorBorderColor] = useState('#494949');
    const [pwErrorBorderColor, setPwErrorBorderColor] = useState('#494949');
    const [rePwErrorBorderColor, setRePwErrorBorderColor] = useState('#494949');

    // 중복체크 버튼 style
    const duplicateCheckButtonStyleTrue = {
        position: "absolute",
        width: "50px",
        height: "40px",
        fontSize: "4px",
        border: "1px solid #494949",
        borderRadius: "8px",
        boxSizing: "border-box",
        backgroundColor: "#000",
        color: "#fff",
        opacity: "1"
    };

    const duplicateCheckButtonStyleFalse = {
        position: "absolute",
        width: "50px",
        height: "40px",
        fontSize: "4px",
        border: "1px solid #494949",
        borderRadius: "8px",
        boxSizing: "border-box",
        backgroundColor: "#000",
        color: "#fff",
        opacity: "0.5"
    };

    const duplicateCheckButtonDisableTrue = true;
    const duplicateCheckButtonDisableFalse = false;

    // 이름 적합성 검사
    const isValidName = userName.length >= 2 && userName.length < 5;

    // 이메일 적합성 검사
    const isValidEmail = userEmail.includes('@') && userEmail.includes('.');

    // 아이디 특수문자 검사를 위한 정규식
    const specialLetterId = userId.search(/[`~!@@#$%^&*|₩₩₩'₩";:₩/?]/gi);

    // 아이디 적합성 검사
    // _를 제외한 모든 특수문자 불허
    const isValidId = specialLetterId <= 0 && userId.length > 5;

    // 비밀번호 특수문자 검사를 위한 정규식
    const specialLetterPw = password.search(/[`~!@@#$%^&*|₩₩₩'₩";:₩/?]/gi);

    // 비밀번호 적합성 검사
    // 특수문자 1개 이상, 전체길이가 8 이상
    const isValidPassword = password.length >= 8 && specialLetterPw >= 1;

    // 비밀번호 일치 적합성 검사
    const isValidPasswordConfirm = passwordConfirm === password;

    // 버튼 활성화 조건
    const isValidInput = userName.length >= 1 && userEmail.length >= 1 && userId.length >= 1 && password.length >= 1 && passwordConfirm.length >= 1;

    const handleDisable = () => {
        isValidName && isValidEmail && isValidPassword && isValidPasswordConfirm && isValidId && isValidInput ? setOpacity(1) : setOpacity(0.5);
        isValidName && isValidEmail && isValidPassword && isValidPasswordConfirm && isValidId && isValidInput ? setDisable(false) : setDisable(true);
    };

    const userNameErrorHandler = () => {
        if (!isValidName) {
            setUserNameShowErrorMessage('한글이름을 입력해 주세요.');
            setUserNameErrorBorderColor('red');
        } else {
            setUserNameShowErrorMessage('이름을 입력해 주세요.');
            setUserNameErrorBorderColor('#494949');
        }
    };

    const userEmailErrorHandler = () => {
        if (!isValidEmail) {
            setUserEmailShowErrorMessage('잘못된 이메일 형식입니다.');
            setUserEmailErrorBorderColor('red');
        } else {
            setUserEmailShowErrorMessage('이메일을 입력해 주세요.');
            setUserEmailErrorBorderColor('#494949');
        }
    };

    const userIdErrorHandler = () => {
        if (!isValidId) {
            setUserIdShowErrorMessage('특수문자를 제외하여 5자 이상이어야합니다.');
            setUserIdErrorBorderColor('red');
        } else {
            setUserIdShowErrorMessage('아이디를 입력해 주세요.');
            setUserIdErrorBorderColor('#494949');
        }
    };

    const pwErrorHandler = () => {
        if (!isValidPassword) {
            setPwShowErrorMessage('특수문자를 포함한 8자 이상이어야합니다.');
            setPwErrorBorderColor('red');
        } else {
            setPwShowErrorMessage('비밀번호를 입력해 주세요.');
            setPwErrorBorderColor('#494949');
        }
    };

    const rePwErrorHandler = () => {
        if (!isValidPasswordConfirm) {
            setRePwShowErrorMessage('비밀번호가 일치하지 않습니다.');
            setRePwErrorBorderColor('red');
        } else {
            setRePwShowErrorMessage('비밀번호를 한번 더 입력해 주세요.');
            setRePwErrorBorderColor('#494949');
        }
    };

    useEffect(() => {
        handleDisable();
    });

    useEffect(() => {
        if (userName.length >= 1) {
            userNameErrorHandler();
        }
    }, [userName])

    useEffect(() => {
        if (userId.length >= 1) {
            userIdErrorHandler();
        }
    }, [userId])

    useEffect(() => {
        if (userEmail.length >= 1) {
            userEmailErrorHandler();
        }
    }, [userEmail])

    useEffect(() => {
        if (password.length >= 1) {
            pwErrorHandler();
        }
    }, [password])

    useEffect(() => {
        rePwErrorHandler();
    }, [passwordConfirm]);

    const handleInput = event => {
        return event.target.value;
    };

    const handleSubmit = (e) => {
        e.preventDefault();
    };


    const navigate = useNavigate();
    const goToLogin = () => {
        navigate('/login');
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
                    <div className="register-rectangle">
                        <form onSubmit={handleSubmit}>
                            <img src="/logos/register-logo.png" width='20%' className="register-logo-img" />
                            <img src="/logos/sub_title.png" width='50%' className="register-title-img" />
                            <h5 className="register-input-name-text" style={{ color: userNameErrorBorderColor }}>{showNameErrorMessage}</h5>
                            <input type='text' className="register-input-name" placeholder="Enter your name" style={{ borderColor: userNameErrorBorderColor }} value={userName} onChange={(event) => {
                                setUserName(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="register-input-mail-text" style={{ color: userEmailErrorBorderColor }}>{showEmailErrorMessage}</h5>
                            <div>
                                <input type='email' className="register-input-mail" placeholder="Enter your e-mail" style={{ borderColor: userEmailErrorBorderColor, marginLeft: "-50px", width: "250px" }} value={userEmail} onChange={(event) => {
                                    setUserEmail(handleInput(event));
                                    handleDisable();
                                }} />
                                <button disabled={isValidEmail ? duplicateCheckButtonDisableFalse : duplicateCheckButtonDisableTrue} style={isValidEmail ? duplicateCheckButtonStyleTrue : duplicateCheckButtonStyleFalse}
                                    onClick={() => {
                                        axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/findEmail', {
                                            params: {
                                                userEmail: userEmail
                                            }
                                        }).then(function (response) {
                                            if (response.data.result) {
                                                setUserEmailShowErrorMessage('존재하는 이메일 입니다.');
                                                setUserEmailErrorBorderColor('red');
                                            } else {
                                                setUserEmailShowErrorMessage('사용가능한 이메일 입니다.');
                                                setUserEmailErrorBorderColor('blue');
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >중복체크</button>
                            </div>
                            <h5 className="register-input-id-text" style={{ color: userIdErrorBorderColor }}>{showIdErrorMessage}</h5>
                            <div>
                                <input type='text' className="register-input-id" placeholder="Enter your I'd" style={{ borderColor: userIdErrorBorderColor, marginLeft: "-50px", width: "250px" }} value={userId} onChange={(event) => {
                                    setUserId(handleInput(event));
                                    handleDisable();
                                }} />
                                <button disabled={userId.length >= 1 && isValidId ? duplicateCheckButtonDisableFalse : duplicateCheckButtonDisableTrue} style={userId.length >= 1 && isValidId ? duplicateCheckButtonStyleTrue : duplicateCheckButtonStyleFalse}
                                    onClick={() => {
                                        axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/findUserId', {
                                            params: {
                                                userId: userId
                                            }
                                        }).then(function (response) {
                                            if (response.data.result) {
                                                setUserIdShowErrorMessage('존재하는 아이디 입니다.');
                                                setUserIdErrorBorderColor('red');
                                            } else {
                                                setUserIdShowErrorMessage('사용가능한 아이디 입니다.');
                                                setUserIdErrorBorderColor('blue');
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >중복체크</button>
                            </div>
                            <h5 className="register-input-pw-text" style={{ color: pwErrorBorderColor }} >{showPwErrorMessage}</h5>
                            <input type='password' className="register-input-pw" placeholder="Enter your password" style={{ borderColor: pwErrorBorderColor }} value={password} onChange={(event) => {
                                setPassword(handleInput(event));
                                handleDisable();
                                pwErrorHandler();
                            }} />
                            <h5 className="register-input-re-pw-text" style={{ color: rePwErrorBorderColor }} >{showRePwErrorMessage}</h5>
                            <input type='password' className="register-input-re-pw" placeholder="Enter re-password" style={{ borderColor: rePwErrorBorderColor }} value={passwordConfirm} onChange={(event) => {
                                setPasswordConfirm(handleInput(event));
                                handleDisable();
                                rePwErrorHandler();
                            }} />
                            <div>
                                <button className="register-button" disabled={disable} style={{ opacity: opacity }}
                                    onClick={() => {
                                        axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/join', {
                                            userName: userName,
                                            userEmail: userEmail,
                                            userId: userId,
                                            password: password
                                        }).then(function (response) {
                                            if (response.data.result === true) {
                                                alert('회원가입이 완료되었습니다.');
                                                goToLogin();
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >가입완료하기</button>
                            </div>
                        </form>
                    </div>
                </div>
            </Desktop >

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
                    <div className="register-rectangle-tablet">
                        <form onSubmit={handleSubmit}>
                            <img src="/logos/register-logo.png" width='20%' className="register-logo-img" />
                            <img src="/logos/sub_title.png" width='50%' className="register-title-img" />
                            <h5 className="register-input-name-text" style={{ color: userNameErrorBorderColor }}>{showNameErrorMessage}</h5>
                            <input type='text' className="register-input-name" placeholder="Enter your name" style={{ borderColor: userNameErrorBorderColor }} value={userName} onChange={(event) => {
                                setUserName(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="register-input-mail-text" style={{ color: userEmailErrorBorderColor }}>{showEmailErrorMessage}</h5>
                            <div>
                                <input type='email' className="register-input-mail" placeholder="Enter your e-mail" style={{ borderColor: userEmailErrorBorderColor, marginLeft: "-50px", width: "250px" }} value={userEmail} onChange={(event) => {
                                    setUserEmail(handleInput(event));
                                    handleDisable();
                                }} />
                                <button disabled={isValidEmail ? duplicateCheckButtonDisableFalse : duplicateCheckButtonDisableTrue} style={isValidEmail ? duplicateCheckButtonStyleTrue : duplicateCheckButtonStyleFalse}
                                    onClick={() => {
                                        axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/checkexistemail', {
                                            params: {
                                                userEmail: userEmail
                                            }
                                        }).then(function (response) {
                                            if (response.data.result) {
                                                setUserEmailShowErrorMessage('존재하는 이메일 입니다.');
                                                setUserEmailErrorBorderColor('red');
                                            } else {
                                                setUserEmailShowErrorMessage('사용가능한 이메일 입니다.');
                                                setUserEmailErrorBorderColor('blue');
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >중복체크</button>
                            </div>
                            <h5 className="register-input-id-text" style={{ color: userIdErrorBorderColor }}>{showIdErrorMessage}</h5>
                            <div>
                                <input type='text' className="register-input-id" placeholder="Enter your I'd" style={{ borderColor: userIdErrorBorderColor, marginLeft: "-50px", width: "250px" }} value={userId} onChange={(event) => {
                                    setUserId(handleInput(event));
                                    handleDisable();
                                }} />
                                <button disabled={userId.length >= 1 && isValidId ? duplicateCheckButtonDisableFalse : duplicateCheckButtonDisableTrue} style={userId.length >= 1 && isValidId ? duplicateCheckButtonStyleTrue : duplicateCheckButtonStyleFalse}
                                    onClick={() => {
                                        axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/checkexistid', {
                                            params: {
                                                userId: userId
                                            }
                                        }).then(function (response) {
                                            if (response.data.result) {
                                                setUserIdShowErrorMessage('존재하는 아이디 입니다.');
                                                setUserIdErrorBorderColor('red');
                                            } else {
                                                setUserIdShowErrorMessage('사용가능한 아이디 입니다.');
                                                setUserIdErrorBorderColor('blue');
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >중복체크</button>
                            </div>
                            <h5 className="register-input-pw-text" style={{ color: pwErrorBorderColor }} >{showPwErrorMessage}</h5>
                            <input type='password' className="register-input-pw" placeholder="Enter your password" style={{ borderColor: pwErrorBorderColor }} value={password} onChange={(event) => {
                                setPassword(handleInput(event));
                                handleDisable();
                                pwErrorHandler();
                            }} />
                            <h5 className="register-input-re-pw-text" style={{ color: rePwErrorBorderColor }} >{showRePwErrorMessage}</h5>
                            <input type='password' className="register-input-re-pw" placeholder="Enter re-password" style={{ borderColor: rePwErrorBorderColor }} value={passwordConfirm} onChange={(event) => {
                                setPasswordConfirm(handleInput(event));
                                handleDisable();
                                rePwErrorHandler();
                            }} />
                            <div>
                                <button className="register-button" disabled={disable} style={{ opacity: opacity }}
                                    onClick={() => {
                                        axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/join', {
                                            userName: userName,
                                            userEmail: userEmail,
                                            userId: userId,
                                            password: password
                                        }).then(function (response) {
                                            if (response.data.result === true) {
                                                alert('회원가입이 완료되었습니다.');
                                                goToLogin();
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >가입완료하기</button>
                            </div>
                        </form>
                    </div>
                </div>
            </Tablet>

            <Mobile>
                <Header />
                <div className="user-bg-mobile">
                    <div className="register-rectangle-mobile">
                        <form onSubmit={handleSubmit}>
                            <img src="/logos/register-logo.png" width='20%' className="register-logo-img" />
                            <img src="/logos/sub_title.png" width='50%' className="register-title-img" />
                            <h5 className="register-input-name-text" style={{ color: userNameErrorBorderColor }}>{showNameErrorMessage}</h5>
                            <input type='text' className="register-input-name" placeholder="Enter your name" style={{ borderColor: userNameErrorBorderColor }} value={userName} onChange={(event) => {
                                setUserName(handleInput(event));
                                handleDisable();
                            }} />
                            <h5 className="register-input-mail-text" style={{ color: userEmailErrorBorderColor }}>{showEmailErrorMessage}</h5>
                            <div>
                                <input type='email' className="register-input-mail" placeholder="Enter your e-mail" style={{ borderColor: userEmailErrorBorderColor, marginLeft: "-50px", width: "250px" }} value={userEmail} onChange={(event) => {
                                    setUserEmail(handleInput(event));
                                    handleDisable();
                                }} />
                                <button disabled={isValidEmail ? duplicateCheckButtonDisableFalse : duplicateCheckButtonDisableTrue} style={isValidEmail ? duplicateCheckButtonStyleTrue : duplicateCheckButtonStyleFalse}
                                    onClick={() => {
                                        axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/checkexistemail', {
                                            params: {
                                                userEmail: userEmail
                                            }
                                        }).then(function (response) {
                                            if (response.data.result) {
                                                setUserEmailShowErrorMessage('존재하는 이메일 입니다.');
                                                setUserEmailErrorBorderColor('red');
                                            } else {
                                                setUserEmailShowErrorMessage('사용가능한 이메일 입니다.');
                                                setUserEmailErrorBorderColor('blue');
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >중복체크</button>
                            </div>
                            <h5 className="register-input-id-text" style={{ color: userIdErrorBorderColor }}>{showIdErrorMessage}</h5>
                            <div>
                                <input type='text' className="register-input-id" placeholder="Enter your I'd" style={{ borderColor: userIdErrorBorderColor, marginLeft: "-50px", width: "250px" }} value={userId} onChange={(event) => {
                                    setUserId(handleInput(event));
                                    handleDisable();
                                }} />
                                <button disabled={userId.length >= 1 && isValidId ? duplicateCheckButtonDisableFalse : duplicateCheckButtonDisableTrue} style={userId.length >= 1 && isValidId ? duplicateCheckButtonStyleTrue : duplicateCheckButtonStyleFalse}
                                    onClick={() => {
                                        axios.get('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/checkexistid', {
                                            params: {
                                                userId: userId
                                            }
                                        }).then(function (response) {
                                            if (response.data.result) {
                                                setUserIdShowErrorMessage('존재하는 아이디 입니다.');
                                                setUserIdErrorBorderColor('red');
                                            } else {
                                                setUserIdShowErrorMessage('사용가능한 아이디 입니다.');
                                                setUserIdErrorBorderColor('blue');
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >중복체크</button>
                            </div>
                            <h5 className="register-input-pw-text" style={{ color: pwErrorBorderColor }} >{showPwErrorMessage}</h5>
                            <input type='password' className="register-input-pw" placeholder="Enter your password" style={{ borderColor: pwErrorBorderColor }} value={password} onChange={(event) => {
                                setPassword(handleInput(event));
                                handleDisable();
                                pwErrorHandler();
                            }} />
                            <h5 className="register-input-re-pw-text" style={{ color: rePwErrorBorderColor }} >{showRePwErrorMessage}</h5>
                            <input type='password' className="register-input-re-pw" placeholder="Enter re-password" style={{ borderColor: rePwErrorBorderColor }} value={passwordConfirm} onChange={(event) => {
                                setPasswordConfirm(handleInput(event));
                                handleDisable();
                                rePwErrorHandler();
                            }} />
                            <div>
                                <button className="register-button" disabled={disable} style={{ opacity: opacity }}
                                    onClick={() => {
                                        axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/join', {
                                            userName: userName,
                                            userEmail: userEmail,
                                            userId: userId,
                                            password: password
                                        }).then(function (response) {
                                            if (response.data.result === true) {
                                                alert('회원가입이 완료되었습니다.');
                                                goToLogin();
                                            }
                                        }).catch(function (error) {
                                            console.error(error);
                                        })
                                    }}
                                >가입완료하기</button>
                            </div>
                        </form>
                    </div>
                </div>
            </Mobile>
        </>
    )
};

export default Register;
