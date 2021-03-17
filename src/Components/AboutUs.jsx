import React from 'react';
import Navbar from './Navbar';
import './AboutUs.css';
import { makeStyles } from '@material-ui/core/styles';
import Container from '@material-ui/core/Container';
import Typography from '@material-ui/core/Typography';
import Link from '@material-ui/core/Link';
import raymonde from './images/Raymonde.jpeg';
import oliver from './images/Oliver.jpg';
import arwa from './images/Arwa.jpg';
import ali from './images/Ali.jpg';

function Copyright() {
    return (
      <Typography variant="body2" color="textSecondary" align="center">
        {'Copyright © '}
        <Link color="inherit" href="/home">
          Viktorina-AI
        </Link>{' '}
        {new Date().getFullYear()}
        {'.'}
      </Typography>
    );
  }
  const useStyles = makeStyles((theme) => ({
     
  
    footer: {
      borderTop: `1px solid ${theme.palette.divider}`,
      marginTop: theme.spacing(8),
      paddingTop: theme.spacing(3),
      paddingBottom: theme.spacing(3),
      [theme.breakpoints.up('sm')]: {
        paddingTop: theme.spacing(6),
        paddingBottom: theme.spacing(6),
      },
    },
  }));
function AboutUs () {
    const classes = useStyles();
      return (
         <Typography>
<Navbar></Navbar>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/MaterialDesign-Webfont/5.3.45/css/materialdesignicons.css" integrity="sha256-NAxhqDvtY0l4xn+YVa6WjAcmd94NNfttjNsDmNatFVc=" crossorigin="anonymous" />

<div class="container bootdey">
        <div class="row">
            <div class="col-12 text-center">
                <div class="section-title mb-4 pb-2">
                    <h4 class="title mb-4">Our Business Minds</h4>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-lg-3 col-md-6 col-12 mt-4 pt-2">
                <div class="team text-center rounded p-3 py-4">
                    <img src={raymonde} class="img-fluid avatar avatar-medium shadow rounded-pill" alt=""/>
                    <div class="content mt-3">
                        <h4 class="title mb-0">Raymonde Akiki</h4>
                        <small class="text-muted">Computer Scientist<br></br> Saint-Joseph University<hr></hr>Lebanon</small>
                        <ul class="list-unstyled mt-3 social-icon social mb-0">
                            <li class="list-inline-item"><a href="https://www.linkedin.com/in/raymonde-akiki-7b046b194/" class="rounded"><i class="mdi mdi-linkedin" title="Linkedin"></i></a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-3 col-md-6 col-12 mt-4 pt-2">
                <div class="team text-center rounded p-3 py-4">
                    <img src={oliver} class="img-fluid avatar avatar-medium shadow rounded-pill" alt=""/>
                    <div class="content mt-3">
                        <h4 class="title mb-0">Oliver Tannous</h4>
                        <small class="text-muted">Computer Scientist<br></br> Saint-Joseph University<hr></hr>Lebanon</small>
                        <ul class="list-unstyled mt-3 social-icon social mb-0">
                        <li class="list-inline-item"><a href="https://www.linkedin.com/in/oliver-tannous-3251411b8/" class="rounded"><i class="mdi mdi-linkedin" title="Linkedin"></i></a></li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-3 col-md-6 col-12 mt-4 pt-2">
                <div class="team text-center rounded p-3 py-4">
                    <img src={arwa}class="img-fluid avatar avatar-medium shadow rounded-pill" alt=""/>
                    <div class="content mt-3">
                        <h4 class="title mb-0">Arwa Almairefi Alyarwan</h4>
                        <small class="text-muted">Computer Scientist<br></br> United Arab Emirates University<hr></hr>UAE</small>                        
                    </div>
                </div>
            </div>
            
            <div class="col-lg-3 col-md-6 col-12 mt-4 pt-2">
               <div class="team text-center rounded p-3 py-4">
                    <img src={ali} class="img-fluid avatar avatar-medium shadow rounded-pill" alt=""/>
                    <div class="content mt-3">
                        <h4 class="title mb-0">Ali Abdo Alshaeir</h4>
                        <small class="text-muted">IT<br></br> United Arab Emirates University<hr></hr>Saudi Arabia</small>
                    </div>
                </div>
            </div>
        </div>
        </div>

        <br></br>
    <div class='colored'>Your best studdy buddy!</div>
    <br></br>
    <div class="idea">
            <div class="col-12 text-center">
                <div class="section-title mb-4 pb-2">
                    <h4 class="title mb-4">The idea</h4>
                    <p class="text-muted para-desc mx-auto mb-0">
                    Ctrl-Alt-Elite, a middle eastern universities students team aiming to make it easier and less time consuming to achieve 
                    high grades by using AI solutions. We hope that our idea inspires others and helps
                    them improve their studying techniques. 
                    Main purpose of AI is to make people’s life easier, so we thought why don’t we use this amazing technology in a 
                    field that no one has come up with any idea to improve it, a field that completely depends on self based efforts.
                    </p>
                </div>
            </div>
            </div>
           

  
    <Container maxWidth="md" component="footer" className={classes.footer} >
      <Copyright/>
      </Container>
      </Typography>
      ); 
  }
  
  export default AboutUs;