import { Accordion, Container } from '@mantine/core';
import ky from 'ky';
import { useEffect, useState } from 'react';
import './App.css';
import { HeaderTabs } from './component/HeaderTabs';

interface Perscription {
  id: string;
  name: string;
  decription: string;
  createdAt: string;
}

interface Patient {
  first: string;
  last: string;
  idCode: number;
}

interface PatientPerscription {
  id: string;
  active: boolean;
  patient: Patient;
  perscription: Perscription;
  issuedAt: Date;
  expiresAt: Date;
}

function App() {
  const [perscriptions, setPerscriptions] = useState<Perscription[]>([]);

  useEffect(() => {
    ky.get('/api/perscriptions/')
      .then((res) => res.json<Perscription[]>())
      .then((data) => setPerscriptions(data));
  }, []);

  return (
    <>
      <HeaderTabs tabs={['Dashboard', 'Perscriptions']} user={{ name: 'User Name', image: '' }} />
      <Container>
        <Accordion variant="contained">
          <Accordion.Item value="Name">
            <Accordion.Control>Name</Accordion.Control>
            <Accordion.Panel>
              <div>dexc</div>
            </Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      </Container>
    </>
  );
}

export default App;
