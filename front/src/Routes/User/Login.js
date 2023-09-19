import { Link, useNavigate } from "react-router-dom";
import { useState, useEffect } from "react";
import { Header } from "../../Components/Header";
import { useMediaQuery } from "react-responsive";
import Cookies from "universal-cookie";
import axios from "axios";

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


// 토큰을 쿠키에 저장하는 함수
export function setRefreshTokenToCookie(refreshToken) {
    cookies.set('refreshToken', refreshToken);
};

export function setAccessTokenToCookie(accessToken) {
    cookies.set('accessToken', accessToken);
};

// 로그아웃 하면 쿠키를 삭제하는 함수.
export function logout() {
    console.log('localStorage set logout!');
    window.localStorage.setItem('logout', Date.now());
    cookies.remove('refreshToken');
    cookies.remove('accessToken');
    localStorage.removeItem('userName');

    return true;
};

// 로그인 여부
export function isLogined() {
    let getCookie = cookies.get("refreshToken");

    if (getCookie) {
        return true;
    }
    return false;
};

// 이름을 로컬세션에 담아두는 함수
export function setLoginUserNameToLS(userName) {
    localStorage.setItem('userName', userName);
};

// 이름 가져오기
export function getLoginUserName() {
    let userName = localStorage.getItem('userName');
    return userName;
};

// 로그인 컴포넌트
function Login() {

    const [userId, setUserId] = useState('');
    const [password, setPassword] = useState('');
    const [disable, setDisable] = useState(true);
    const [opacity, setOpacity] = useState(0.5);

    const navigate = useNavigate();
    const goToList = () => {
        navigate('/');
    };

    useEffect(() => {
        handleDisable();
    });

    const handleInput = event => {
        return event.target.value;
    };

    const handleDisable = () => {
        userId && password ? setOpacity(1) : setOpacity(0.5);
        userId && password ? setDisable(false) : setDisable(true);
    };

    let nevigate = useNavigate();

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
                    <div className="login-rectangle">
                        <img src="/logos/login_logo.png" width='20%' className="login-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="login-title-img" />
                        <input type='text' className="login-input-id" placeholder="Enter i'd" value={userId} onChange={(event) => {
                            setUserId(handleInput(event));
                            handleDisable();
                        }} />
                        <div className="login-find-id">
                            <Link to='/findid'>아이디를 잊어버렸어요.</Link>
                        </div>
                        <input type='password' className="login-input-pw" placeholder="Enter password" value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            handleDisable();
                        }} />
                        <div className="login-find-pw">
                            <Link to='/FindPw'>비밀번호를 잊어버렸어요.</Link>
                        </div>
                        <div>
                            <button type="submit" className="login-button" disabled={disable} style={{ opacity: opacity }} onClick={() => {
                                axios.post("http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/login", {
                                    userId: userId,
                                    password: password
                                }).then(function (respons) {

                                    setRefreshTokenToCookie(respons.headers.get("RT_Authorization"));
                                    setAccessTokenToCookie(respons.headers.get("AT_Authorization"));
                                    setLoginUserNameToLS(respons.data.userName);

                                    if (respons.data.result == 'false') {
                                        alert(respons.data.message);
                                        cookies.remove('refreshToken');
                                    } else {
                                        goToList();
                                    }
                                }).catch(function (error) {
                                    console.error(error);
                                })
                            }}>Login</button>
                        </div>
                        <div className="create-account">
                            <Link to='/Register'>Create Account</Link>
                        </div>
                        <div className="sns-login-buttons">
                            <button type="button" className="google-login">
                                <img src="/logos/google_logo.png" width='50%' />
                            </button>
                            <button type="button" className="facebook-login">
                                <img src="/logos/facebook_logo.png" width='50%' />
                            </button>
                            <button type="button" className="apple-login">
                                <img src="/logos/apple_logo.png" width='50%' />
                            </button>
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
                    <div className="login-rectangle-tablet">
                        <img src="/logos/login_logo.png" width='20%' className="login-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="login-title-img" />
                        <input type='text' className="login-input-id" placeholder="Enter i'd" value={userId} onChange={(event) => {
                            setUserId(handleInput(event));
                            handleDisable();
                        }} />
                        <div className="login-find-id">
                            <Link to='/findid'>아이디를 잊어버렸어요.</Link>
                        </div>
                        <input type='password' className="login-input-pw" placeholder="Enter password" value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            handleDisable();
                        }} />
                        <div className="login-find-pw">
                            <Link to='/FindPw'>비밀번호를 잊어버렸어요.</Link>
                        </div>
                        <div>
                            <button type="submit" className="login-button" disabled={disable} style={{ opacity: opacity }} onClick={() => {
                                axios.post("http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/login", {
                                    userId: userId,
                                    password: password
                                }).then(function (respons) {

                                    setRefreshTokenToCookie(respons.headers.get("RT_Authorization"));
                                    setAccessTokenToCookie(respons.headers.get("AT_Authorization"));
                                    setLoginUserNameToLS(respons.data.userName);

                                    if (respons.data.result == 'false') {
                                        alert(respons.data.message);
                                        cookies.remove('refreshToken');
                                    } else {
                                        goToList();
                                    }
                                }).catch(function (error) {
                                    console.error(error);
                                })
                            }}>Login</button>
                        </div>
                        <div className="create-account">
                            <Link to='/Register'>Create Account</Link>
                        </div>
                        <div className="sns-login-buttons">
                            <button type="button" className="google-login">
                                <img src="/logos/google_logo.png" width='50%' />
                            </button>
                            <button type="button" className="facebook-login">
                                <img src="/logos/facebook_logo.png" width='50%' />
                            </button>
                            <button type="button" className="apple-login">
                                <img src="/logos/apple_logo.png" width='50%' />
                            </button>
                        </div>
                    </div>
                </div>
            </Tablet>
            <Mobile>
                <Header />
                <div className="user-bg-mobile">
                    <div className="login-rectangle-mobile">
                        <img src="/logos/login_logo.png" width='20%' className="login-logo-img" />
                        <img src="/logos/sub_title.png" width='50%' className="login-title-img" />
                        <input type='text' className="login-input-id" placeholder="Enter i'd" value={userId} onChange={(event) => {
                            setUserId(handleInput(event));
                            handleDisable();
                        }} />
                        <div className="login-find-id">
                            <Link to='/findid'>아이디를 잊어버렸어요.</Link>
                        </div>
                        <input type='password' className="login-input-pw" placeholder="Enter password" value={password} onChange={(event) => {
                            setPassword(handleInput(event));
                            handleDisable();
                        }} />
                        <div className="login-find-pw">
                            <Link to='/FindPw'>비밀번호를 잊어버렸어요.</Link>
                        </div>
                        <div>
                            <button type="submit" className="login-button" disabled={disable} style={{ opacity: opacity }} onClick={() => {
                                axios.post("http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/login", {
                                    userId: userId,
                                    password: password
                                }).then(function (respons) {

                                    setRefreshTokenToCookie(respons.headers.get("RT_Authorization"));
                                    setAccessTokenToCookie(respons.headers.get("AT_Authorization"));
                                    setLoginUserNameToLS(respons.data.userName);

                                    if (respons.data.result == 'false') {
                                        alert(respons.data.message);
                                        cookies.remove('refreshToken');
                                    } else {
                                        goToList();
                                    }
                                }).catch(function (error) {
                                    console.error(error);
                                })
                            }}>Login</button>
                        </div>
                        <div className="create-account">
                            <Link to='/Register'>Create Account</Link>
                        </div>
                        <div className="sns-login-buttons">
                            <button type="button" className="google-login">
                                <img src="/logos/google_logo.png" width='50%' />
                            </button>
                            <button type="button" className="facebook-login">
                                <img src="/logos/facebook_logo.png" width='50%' />
                            </button>
                            <button type="button" className="apple-login">
                                <img src="/logos/apple_logo.png" width='50%' />
                            </button>
                        </div>
                    </div>
                </div>
            </Mobile>
        </>
    )
};

export default Login;